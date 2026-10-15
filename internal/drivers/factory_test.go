package drivers

import (
	"testing"

	"github.com/lucaswilliameufrasio/shared-resource-provisioner/internal/config"
)

func TestNewConfiguredServiceKeepsMutationsDisabledByDefault(t *testing.T) {
	t.Parallel()

	settings := config.Settings{}
	if settings.MutationsEnabled {
		t.Fatal("mutations must remain disabled by default")
	}
	if _, _, err := NewConfiguredService(settings, nil, nil, nil); err == nil || err.Error() != "resource mutations are disabled" {
		t.Fatal("NewConfiguredService() did not reject disabled mutations before loading configuration")
	}
}
