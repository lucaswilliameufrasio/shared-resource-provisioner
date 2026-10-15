package provisioning

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/identity"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/persistence/sqlite"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/secrets"
)

func TestCreateInspectAndRevokeLifecycleKeepsCredentialOutOfViews(t *testing.T) {
	t.Parallel()

	store := openTestStore(t)
	grantTestActions(t, store, authorization.ActionCreateResource, authorization.ActionInspectResource, authorization.ActionRevokeResource)
	driver := &testDriver{}
	secretStore := newTestSecretStore()
	service := newTestService(t, store, driver, secretStore)
	ctx := identity.WithPrincipal(context.Background(), identity.Principal{Subject: "caller-subject", Transport: identity.TransportStdio})
	command := domain.CreateResourceCommand{
		ResourceType:   domain.ResourcePostgreSQL,
		Scope:          domain.Scope{Application: "orders", Environment: "production"},
		IdempotencyKey: "create-request-001",
	}

	created, err := service.Create(ctx, command)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.Status != domain.ResourceActive || created.SecretReference == "" || driver.createCalls != 1 {
		t.Fatalf("created resource = %+v; create calls = %d", created, driver.createCalls)
	}
	encoded, err := json.Marshal(created)
	if err != nil {
		t.Fatalf("Marshal(created) error = %v", err)
	}
	if bytes.Contains(encoded, driver.lastCredential) {
		t.Fatal("resource view exposed generated credential bytes")
	}

	repeated, err := service.Create(ctx, command)
	if err != nil {
		t.Fatalf("Create(replay) error = %v", err)
	}
	if repeated.ID != created.ID || driver.createCalls != 1 {
		t.Fatalf("idempotent create changed resource or repeated driver work: %+v, calls=%d", repeated, driver.createCalls)
	}

	inspected, err := service.Inspect(ctx, created.ID)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if inspected.ID != created.ID || inspected.SecretReference != created.SecretReference {
		t.Fatalf("Inspect() = %+v", inspected)
	}

	_, err = service.Revoke(ctx, domain.RevokeResourceCommand{ResourceID: created.ID, Confirmation: "no"}, "revoke-request-001")
	if !errors.Is(err, domain.ErrInvalidResourceTransition) {
		t.Fatalf("Revoke(invalid confirmation) error = %v", err)
	}
	revoked, err := service.Revoke(ctx, domain.RevokeResourceCommand{
		ResourceID:   created.ID,
		Confirmation: "revoke:" + created.ID,
	}, "revoke-request-001")
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if revoked.Status != domain.ResourceRevoked || revoked.SecretReference != "" || driver.revokeCalls != 1 {
		t.Fatalf("revoked resource = %+v; revoke calls = %d", revoked, driver.revokeCalls)
	}
	if len(secretStore.values) != 0 {
		t.Fatalf("secret store retained %d credential references after revoke", len(secretStore.values))
	}
	revokedAgain, err := service.Revoke(ctx, domain.RevokeResourceCommand{
		ResourceID:   created.ID,
		Confirmation: "revoke:" + created.ID,
	}, "revoke-request-001")
	if err != nil || revokedAgain.Status != domain.ResourceRevoked || driver.revokeCalls != 1 {
		t.Fatalf("idempotent Revoke() = %+v, %v; calls=%d", revokedAgain, err, driver.revokeCalls)
	}
	inspected, err = service.Inspect(ctx, created.ID)
	if err != nil || inspected.SecretReference != "" {
		t.Fatalf("Inspect(revoked) = %+v, %v", inspected, err)
	}
}

func TestCreateRetriesKnownFailureWithSameIdempotencyKey(t *testing.T) {
	t.Parallel()

	store := openTestStore(t)
	grantTestActions(t, store, authorization.ActionCreateResource)
	driver := &testDriver{createErrors: []error{NewDriverFailure("TARGET_UNAVAILABLE", false)}}
	service := newTestService(t, store, driver, newTestSecretStore())
	ctx := identity.WithPrincipal(context.Background(), identity.Principal{Subject: "caller-subject", Transport: identity.TransportStdio})
	command := domain.CreateResourceCommand{
		ResourceType:   domain.ResourceValkey,
		Scope:          domain.Scope{Application: "orders", Environment: "production"},
		IdempotencyKey: "create-retry-001",
	}

	if _, err := service.Create(ctx, command); !errors.Is(err, ErrProvisioningFailed) {
		t.Fatalf("Create(first attempt) error = %v, want ErrProvisioningFailed", err)
	}
	resource, err := store.GetResource(context.Background(), mustResourceIDForOperation(t, store, "caller-subject", command.IdempotencyKey))
	if err != nil || resource.Status != domain.ResourceFailed {
		t.Fatalf("failed resource = %+v, %v", resource, err)
	}
	created, err := service.Create(ctx, command)
	if err != nil {
		t.Fatalf("Create(retry) error = %v", err)
	}
	if created.Status != domain.ResourceActive || driver.createCalls != 2 || driver.revokeCalls != 0 {
		t.Fatalf("retry result = %+v; create=%d revoke=%d", created, driver.createCalls, driver.revokeCalls)
	}
}

func TestCreateCompensatesPartialProvisioningAndMarksUnknownFailureForReconciliation(t *testing.T) {
	t.Parallel()

	store := openTestStore(t)
	grantTestActions(t, store, authorization.ActionCreateResource)
	driver := &testDriver{
		createErrors: []error{NewDriverFailure("DRIVER_FAILURE", true)},
		revokeErrors: []error{errors.New("untrusted upstream text")},
	}
	service := newTestService(t, store, driver, newTestSecretStore())
	ctx := identity.WithPrincipal(context.Background(), identity.Principal{Subject: "caller-subject", Transport: identity.TransportStdio})
	command := domain.CreateResourceCommand{
		ResourceType:   domain.ResourceNATS,
		Scope:          domain.Scope{Application: "orders", Environment: "production"},
		IdempotencyKey: "create-reconcile-001",
	}

	if _, err := service.Create(ctx, command); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("Create(uncertain failure) error = %v, want ErrReconciliationRequired", err)
	}
	resourceID := mustResourceIDForOperation(t, store, "caller-subject", command.IdempotencyKey)
	resource, err := store.GetResource(context.Background(), resourceID)
	if err != nil || resource.Status != domain.ResourceReconciliation || resource.ErrorCode != "COMPENSATION_FAILED" {
		t.Fatalf("reconciliation resource = %+v, %v", resource, err)
	}
	created, err := service.Create(ctx, command)
	if err != nil {
		t.Fatalf("Create(reconciliation retry) error = %v", err)
	}
	if created.Status != domain.ResourceActive || driver.createCalls != 2 || driver.revokeCalls != 1 {
		t.Fatalf("reconciliation retry = %+v; create=%d revoke=%d", created, driver.createCalls, driver.revokeCalls)
	}
}

func TestCreateDeniesWithoutGrantAndDoesNotCallDriver(t *testing.T) {
	t.Parallel()

	store := openTestStore(t)
	driver := &testDriver{}
	auditor := &recordingAuditor{delegate: store}
	service := newTestService(t, store, driver, newTestSecretStore(), auditor)
	ctx := identity.WithPrincipal(context.Background(), identity.Principal{Subject: "caller-subject", Transport: identity.TransportStdio})
	_, err := service.Create(ctx, domain.CreateResourceCommand{
		ResourceType:   domain.ResourcePostgreSQL,
		Scope:          domain.Scope{Application: "orders", Environment: "production"},
		IdempotencyKey: "create-denied-001",
	})
	if !errors.Is(err, authorization.ErrPermissionDenied) || driver.createCalls != 0 {
		t.Fatalf("Create(denied) error = %v; driver calls = %d", err, driver.createCalls)
	}
	deniedAudits := 0
	for _, event := range auditor.events {
		if event.Action == string(authorization.ActionCreateResource) && event.Outcome == audit.OutcomeDenied {
			deniedAudits++
		}
	}
	if deniedAudits != 1 {
		t.Fatalf("denied audit count = %d, want 1", deniedAudits)
	}
}

type testDriver struct {
	createCalls    int
	revokeCalls    int
	createErrors   []error
	revokeErrors   []error
	lastCredential []byte
}

func (driver *testDriver) Create(_ context.Context, resource domain.Resource) (Credential, error) {
	driver.createCalls++
	if len(driver.createErrors) > 0 {
		err := driver.createErrors[0]
		driver.createErrors = driver.createErrors[1:]
		return Credential{}, err
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return Credential{}, err
	}
	driver.lastCredential = append(driver.lastCredential[:0], value...)
	return Credential{Name: credentialName(resource.ResourceType), Value: value}, nil
}

func (driver *testDriver) Revoke(context.Context, domain.Resource) error {
	driver.revokeCalls++
	if len(driver.revokeErrors) == 0 {
		return nil
	}
	err := driver.revokeErrors[0]
	driver.revokeErrors = driver.revokeErrors[1:]
	return err
}

type testSecretStore struct {
	values map[string][]byte
}

type recordingAuditor struct {
	delegate audit.Recorder
	events   []audit.Event
}

func (recorder *recordingAuditor) Record(ctx context.Context, event audit.Event) error {
	recorder.events = append(recorder.events, event)
	return recorder.delegate.Record(ctx, event)
}

func newTestSecretStore() *testSecretStore {
	return &testSecretStore{values: make(map[string][]byte)}
}

func (store *testSecretStore) ReferenceFor(scope domain.Scope, name string) (secrets.Reference, error) {
	return secrets.NewReference("test-project", scope, name)
}

func (store *testSecretStore) Put(_ context.Context, scope domain.Scope, name string, value []byte) (secrets.Reference, error) {
	reference, err := store.ReferenceFor(scope, name)
	if err != nil {
		return secrets.Reference{}, err
	}
	store.values[reference.URI] = append([]byte(nil), value...)
	return reference, nil
}

func (store *testSecretStore) Delete(_ context.Context, reference secrets.Reference) error {
	if err := secrets.ValidateReference(reference); err != nil {
		return err
	}
	if value, exists := store.values[reference.URI]; exists {
		clear(value)
		delete(store.values, reference.URI)
	}
	return nil
}

func openTestStore(t *testing.T) *sqlite.Store {
	t.Helper()

	store, err := sqlite.Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Store.Close() error = %v", err)
		}
	})
	return store
}

func grantTestActions(t *testing.T, store *sqlite.Store, actions ...authorization.Action) {
	t.Helper()
	for _, action := range actions {
		_, err := store.CreateGrant(context.Background(), authorization.GrantRecord{
			Subject:     "caller-subject",
			Application: "orders",
			Environment: "production",
			Action:      action,
		}, audit.Event{Subject: "admin-subject", Action: "grant.create", Outcome: audit.OutcomeAllowed})
		if err != nil {
			t.Fatalf("CreateGrant(%q) error = %v", action, err)
		}
	}
}

func newTestService(t *testing.T, store *sqlite.Store, driver Driver, secretStore secrets.SecretStore, auditors ...audit.Recorder) *Service {
	t.Helper()
	authorizer, err := authorization.NewPersistentAuthorizer(store)
	if err != nil {
		t.Fatalf("NewPersistentAuthorizer() error = %v", err)
	}
	var auditor audit.Recorder = store
	if len(auditors) > 0 {
		auditor = auditors[0]
	}
	service, err := NewService(store, authorizer, auditor, secretStore, []Target{
		{
			ID:                      "target-primary",
			ResourceType:            domain.ResourcePostgreSQL,
			MaxResources:            10,
			MaxConcurrentOperations: 2,
			Driver:                  driver,
		},
		{
			ID:                      "target-valkey",
			ResourceType:            domain.ResourceValkey,
			MaxResources:            10,
			MaxConcurrentOperations: 2,
			Driver:                  driver,
		},
		{
			ID:                      "target-nats",
			ResourceType:            domain.ResourceNATS,
			MaxResources:            10,
			MaxConcurrentOperations: 2,
			Driver:                  driver,
		},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func mustResourceIDForOperation(t *testing.T, store *sqlite.Store, subject string, idempotencyKey string) string {
	t.Helper()

	operation, err := store.GetOperationByIdempotencyKey(context.Background(), subject, idempotencyKey)
	if err != nil {
		t.Fatalf("GetOperationByIdempotencyKey() error = %v", err)
	}
	return operation.ResourceID
}
