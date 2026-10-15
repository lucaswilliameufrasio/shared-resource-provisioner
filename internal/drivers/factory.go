package drivers

import (
	"errors"
	"sync"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/audit"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/authorization"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/domain"
	natsdriver "github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/drivers/nats"
	pgdriver "github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/drivers/postgresql"
	valkeydriver "github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/drivers/valkey"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/provisioning"
	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/secrets/ciphera"
)

type closer interface {
	Close()
}

type managedDriver interface {
	provisioning.Driver
	closer
}

type Resources struct {
	mu      sync.Mutex
	closers []closer
	closed  bool
}

func (resources *Resources) Close() {
	resources.mu.Lock()
	defer resources.mu.Unlock()
	if resources.closed {
		return
	}
	for index := len(resources.closers) - 1; index >= 0; index-- {
		resources.closers[index].Close()
	}
	resources.closers = nil
	resources.closed = true
}

func NewConfiguredService(
	settings config.Settings,
	store provisioning.ResourceStore,
	authorizer authorization.Authorizer,
	auditor audit.Recorder,
) (*provisioning.Service, *Resources, error) {
	if !settings.MutationsEnabled {
		return nil, nil, errors.New("resource mutations are disabled")
	}
	targets, err := config.LoadTargetFile(settings.TargetFile)
	if err != nil {
		return nil, nil, errors.New("service target configuration is invalid")
	}
	cipheraSettings, err := config.LoadCipheraFile(settings.CipheraFile)
	if err != nil {
		return nil, nil, errors.New("secret-store configuration is invalid")
	}
	serviceKey, err := config.ReadSecretFile(cipheraSettings.ServiceKeyFile)
	if err != nil {
		return nil, nil, errors.New("secret-store service key file is invalid")
	}
	secretStore, err := ciphera.NewStore(cipheraSettings, serviceKey, nil)
	clear(serviceKey)
	if err != nil {
		return nil, nil, errors.New("secret store could not be initialized")
	}
	resources := &Resources{closers: []closer{secretStore}}
	provisioningTargets := make([]provisioning.Target, 0, len(targets.Targets))
	for _, target := range targets.Targets {
		serviceDriver, err := newDriver(target)
		if err != nil {
			resources.Close()
			return nil, nil, errors.New("service target driver could not be initialized")
		}
		resources.closers = append(resources.closers, serviceDriver)
		provisioningTargets = append(provisioningTargets, provisioning.Target{
			ID:                      target.ID,
			ResourceType:            target.ResourceType,
			MaxResources:            target.MaxResources,
			MaxConcurrentOperations: target.MaxConcurrentOperations,
			Driver:                  serviceDriver,
		})
	}
	service, err := provisioning.NewService(store, authorizer, auditor, secretStore, provisioningTargets)
	if err != nil {
		resources.Close()
		return nil, nil, errors.New("resource provisioning service could not be initialized")
	}
	return service, resources, nil
}

func newDriver(target config.Target) (managedDriver, error) {
	endpoint, err := config.ReadSecretFile(target.EndpointFile)
	if err != nil {
		return nil, errors.New("service target endpoint file is invalid")
	}
	defer clear(endpoint)

	switch target.ResourceType {
	case domain.ResourcePostgreSQL:
		return pgdriver.New(target, endpoint)
	case domain.ResourceValkey:
		return valkeydriver.New(target, endpoint)
	case domain.ResourceNATS:
		operatorSeed, err := config.ReadSecretFile(target.NATSOperatorSeedFile)
		if err != nil {
			return nil, errors.New("NATS operator seed file is invalid")
		}
		defer clear(operatorSeed)
		systemCredentials, err := config.ReadSecretFile(target.NATSSystemCredentialsFile)
		if err != nil {
			return nil, errors.New("NATS system credentials file is invalid")
		}
		defer clear(systemCredentials)
		return natsdriver.New(target, endpoint, operatorSeed, systemCredentials)
	default:
		return nil, errors.New("unsupported service target")
	}
}
