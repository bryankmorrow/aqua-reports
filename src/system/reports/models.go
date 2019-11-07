package reports

// VulnerabilityResource is used in the ResourceReport below
type VulnerabilityResource struct {
	Name       string
	Severity   string
	Score      float64
	URL        string
	FixVersion string
}

// ResourceReport is used to create the Vulnerabilities Tab in HTML Report
type ResourceReport struct {
	Type          string
	Format        string
	Path          string
	Name          string
	Version       string
	Arch          string
	Vulnerability []VulnerabilityResource
}
