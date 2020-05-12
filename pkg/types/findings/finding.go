package findings

import (
	"github.com/BryanKMorrow/aqua-reports/pkg/types/images"
	"github.com/BryanKMorrow/aqua-reports/pkg/types/registries"
)

// Finding represents the vulnerability report
type Finding struct {
	Registries  []registries.RegistryFinding `json:"registries"`
	Images      []images.ImageFinding        `json:"images"`
	ScanHistory []images.ScanHistoryFinding  `json:"scan_history"`
	Template    string                       `json:"template"`
}
