package registries

import "github.com/BryanKMorrow/aqua-reports/pkg/types/images"

type RegistryFinding struct {
	Name          string                `json:"name"`
	Type          string                `json:"type"`
	DetectedType  int                   `json:"detected_type"`
	Description   string                `json:"description"`
	Author        string                `json:"author"`
	Lastupdate    int                   `json:"lastupdate"`
	URL           string                `json:"url"`
	Username      string                `json:"username"`
	ImageCount    int                   `json:"image_count"`
	TotalVulns    int                   `json:"total_vulns"`
	CritVulns     int                   `json:"crit_vulns"`
	HighVulns     int                   `json:"high_vulns"`
	MedVulns      int                   `json:"med_vulns"`
	LowVulns      int                   `json:"low_vulns"`
	Malware       int                   `json:"malware"`
	SensitiveData int                   `json:"sensitive_data"`
	Images        []images.ImageFinding `json:"images"`
}
