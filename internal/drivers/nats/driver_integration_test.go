//go:build integration

package natsdriver

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestDriverProvisionsIsolatesLimitsAndRevokesAgainstLocalNATS(t *testing.T) {
	endpoint, operatorSeed, systemCredentials, stopServer := startLocalNATS(t)
	defer stopServer()
	defer clear(operatorSeed)
	defer clear(systemCredentials)

	target := integrationTarget()
	driver, err := New(target, []byte(endpoint), operatorSeed, systemCredentials)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer driver.Close()

	resource := domain.Resource{
		ID:           "local-resource-one",
		ResourceType: domain.ResourceNATS,
		Scope:        domain.Scope{Application: "orders", Environment: "test"},
	}
	firstCredential, err := driver.Create(context.Background(), resource)
	if err != nil {
		t.Fatalf("Create(first resource) error = %v", err)
	}
	defer clear(firstCredential.Value)
	firstClaims, firstSeed, err := parseCredentials(firstCredential.Value)
	if err != nil {
		t.Fatalf("parseCredentials(first) error = %v", err)
	}
	defer clear(firstClaims)
	defer clear(firstSeed)
	firstUserClaims, err := jwt.DecodeUserClaims(string(firstClaims))
	if err != nil {
		t.Fatalf("DecodeUserClaims(first) error = %v", err)
	}

	retryCredential, err := driver.Create(context.Background(), resource)
	if err != nil {
		t.Fatalf("Create(retry) error = %v", err)
	}
	defer clear(retryCredential.Value)
	retryClaims, retrySeed, err := parseCredentials(retryCredential.Value)
	if err != nil {
		t.Fatalf("parseCredentials(retry) error = %v", err)
	}
	defer clear(retryClaims)
	defer clear(retrySeed)
	retryUserClaims, err := jwt.DecodeUserClaims(string(retryClaims))
	if err != nil {
		t.Fatalf("DecodeUserClaims(retry) error = %v", err)
	}
	if firstUserClaims.Subject != retryUserClaims.Subject || !equalBytes(firstSeed, retrySeed) {
		t.Fatal("retry did not recover the same resource user identity")
	}

	firstConnection := connectResourceUser(t, endpoint, firstCredential.Value)
	defer firstConnection.Close()
	if extraConnection, err := openResourceUser(endpoint, firstCredential.Value); err == nil {
		extraConnection.Close()
		t.Fatal("NATS accepted a connection above the resource account limit")
	}
	firstSubscription, err := firstConnection.SubscribeSync("orders.created")
	if err != nil {
		t.Fatalf("SubscribeSync() error = %v", err)
	}
	if err := firstConnection.FlushTimeout(5 * time.Second); err != nil {
		t.Fatalf("FlushTimeout() error = %v", err)
	}
	if err := firstConnection.Publish("orders.created", []byte("local-test")); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if _, err := firstSubscription.NextMsg(5 * time.Second); err != nil {
		t.Fatalf("NextMsg() error = %v", err)
	}
	jetStream, err := firstConnection.JetStream()
	if err != nil {
		t.Fatalf("JetStream() error = %v", err)
	}
	if _, err := jetStream.AddStream(&nats.StreamConfig{
		Name:     "ORDERS",
		Subjects: []string{"orders.>"},
		Storage:  nats.MemoryStorage,
		MaxBytes: 1 << 20,
	}); err != nil {
		t.Fatalf("AddStream() error = %v", err)
	}
	if _, err := jetStream.AddStream(&nats.StreamConfig{
		Name:     "BILLING",
		Subjects: []string{"billing.>"},
		Storage:  nats.MemoryStorage,
		MaxBytes: 1 << 20,
	}); err == nil {
		t.Fatal("NATS accepted a stream above the account JetStream stream limit")
	}

	secondResource := resource
	secondResource.ID = "local-resource-two"
	secondCredential, err := driver.Create(context.Background(), secondResource)
	if err != nil {
		t.Fatalf("Create(second resource) error = %v", err)
	}
	defer clear(secondCredential.Value)
	secondConnection := connectResourceUser(t, endpoint, secondCredential.Value)
	defer secondConnection.Close()
	if err := secondConnection.Publish("orders.created", []byte("isolated-test")); err != nil {
		t.Fatalf("Publish(second account) error = %v", err)
	}
	if _, err := firstSubscription.NextMsg(100 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("first account received a message from a distinct account: %v", err)
	}

	if err := driver.Revoke(context.Background(), resource); err != nil {
		t.Fatalf("Revoke(first resource) error = %v", err)
	}
	if _, err := nats.Connect(endpoint,
		nats.UserJWTAndSeed(string(firstClaims), string(firstSeed)),
		nats.Timeout(3*time.Second),
		nats.MaxReconnects(0),
	); err == nil {
		t.Fatal("NATS accepted a user credential after its account revocation was published")
	}
	if err := driver.Revoke(context.Background(), resource); err != nil {
		t.Fatalf("Revoke(retry) error = %v", err)
	}
}

func startLocalNATS(t *testing.T) (string, []byte, []byte, func()) {
	t.Helper()

	operator, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatalf("CreateOperator() error = %v", err)
	}
	t.Cleanup(operator.Wipe)
	operatorSeed, err := operator.Seed()
	if err != nil {
		t.Fatalf("Seed(operator) error = %v", err)
	}
	operatorPublic, err := operator.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(operator) error = %v", err)
	}
	systemAccount, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("CreateAccount(system) error = %v", err)
	}
	t.Cleanup(systemAccount.Wipe)
	systemAccountPublic, err := systemAccount.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(system account) error = %v", err)
	}
	systemAccountClaims := jwt.NewAccountClaims(systemAccountPublic)
	systemAccountJWT, err := systemAccountClaims.Encode(operator)
	if err != nil {
		t.Fatalf("Encode(system account) error = %v", err)
	}
	systemUser, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("CreateUser(system) error = %v", err)
	}
	t.Cleanup(systemUser.Wipe)
	systemUserPublic, err := systemUser.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(system user) error = %v", err)
	}
	systemUserClaims := jwt.NewUserClaims(systemUserPublic)
	systemUserClaims.IssuerAccount = systemAccountPublic
	systemUserClaims.Permissions = jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{">"}},
		Sub: jwt.Permission{Allow: jwt.StringList{">"}},
	}
	systemUserJWT, err := systemUserClaims.Encode(systemAccount)
	if err != nil {
		t.Fatalf("Encode(system user) error = %v", err)
	}
	systemUserSeed, err := systemUser.Seed()
	if err != nil {
		t.Fatalf("Seed(system user) error = %v", err)
	}
	systemCredentials := encodeCredentials(systemUserJWT, systemUserSeed)
	clear(systemUserSeed)

	operatorClaims := jwt.NewOperatorClaims(operatorPublic)
	operatorClaims.SystemAccount = systemAccountPublic
	resolver, err := server.NewDirAccResolver(filepath.Join(t.TempDir(), "account-jwts"), 100, time.Minute, server.NoDelete)
	if err != nil {
		t.Fatalf("NewDirAccResolver() error = %v", err)
	}
	if err := resolver.Store(systemAccountPublic, systemAccountJWT); err != nil {
		resolver.Close()
		t.Fatalf("Store(system account) error = %v", err)
	}
	natsServer, err := server.NewServer(&server.Options{
		ServerName:             "shared-resource-provisioner-test",
		Host:                   "127.0.0.1",
		Port:                   -1,
		NoLog:                  true,
		NoSigs:                 true,
		JetStream:              true,
		JetStreamMaxMemory:     64 << 20,
		JetStreamMaxStore:      64 << 20,
		StoreDir:               filepath.Join(t.TempDir(), "jetstream"),
		DisableJetStreamBanner: true,
		TrustedOperators:       []*jwt.OperatorClaims{operatorClaims},
		SystemAccount:          systemAccountPublic,
		AccountResolver:        resolver,
	})
	if err != nil {
		resolver.Close()
		clear(systemCredentials)
		t.Fatalf("NewServer() error = %v", err)
	}
	go natsServer.Start()
	if !natsServer.ReadyForConnections(10 * time.Second) {
		natsServer.Shutdown()
		natsServer.WaitForShutdown()
		clear(systemCredentials)
		t.Fatal("local NATS server did not become ready")
	}
	stop := func() {
		natsServer.Shutdown()
		natsServer.WaitForShutdown()
	}
	return natsServer.ClientURL(), operatorSeed, systemCredentials, stop
}

func connectResourceUser(t *testing.T, endpoint string, credentials []byte) *nats.Conn {
	t.Helper()
	connection, err := openResourceUser(endpoint, credentials)
	if err != nil {
		t.Fatal("NATS application connection was rejected")
	}
	return connection
}

func openResourceUser(endpoint string, credentials []byte) (*nats.Conn, error) {
	userJWT, userSeed, err := parseCredentials(credentials)
	if err != nil {
		return nil, err
	}
	defer clear(userJWT)
	defer clear(userSeed)
	connection, err := nats.Connect(endpoint,
		nats.UserJWTAndSeed(string(userJWT), string(userSeed)),
		nats.Timeout(5*time.Second),
		nats.MaxReconnects(0),
	)
	return connection, err
}

func integrationTarget() config.Target {
	return config.Target{
		ID:                        "nats-integration",
		ResourceType:              domain.ResourceNATS,
		MaxResources:              10,
		MaxConcurrentOperations:   2,
		NATSMaxConnections:        1,
		NATSMaxSubscriptions:      50,
		NATSMaxPayloadBytes:       1 << 20,
		NATSJetStreamMemoryBytes:  8 << 20,
		NATSJetStreamDiskBytes:    8 << 20,
		NATSJetStreamMaxStreams:   1,
		NATSJetStreamMaxConsumers: 3,
	}
}

func equalBytes(left []byte, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
