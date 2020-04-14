package images

import (
	"time"
)

type ImageFinding struct {
	Registry              string               `json:"registry"`
	Name                  string               `json:"name"`
	VulnsFound            int                  `json:"vulns_found"`
	CritVulns             int                  `json:"crit_vulns"`
	HighVulns             int                  `json:"high_vulns"`
	MedVulns              int                  `json:"med_vulns"`
	LowVulns              int                  `json:"low_vulns"`
	NegVulns              int                  `json:"neg_vulns"`
	FixableVulns          int                  `json:"fixable_vulns"`
	RegistryType          string               `json:"registry_type"`
	Repository            string               `json:"repository"`
	Tag                   string               `json:"tag"`
	Created               time.Time            `json:"created"`
	Author                string               `json:"author"`
	Digest                string               `json:"digest"`
	Size                  int                  `json:"size"`
	Os                    string               `json:"os"`
	OsVersion             string               `json:"os_version"`
	ScanStatus            string               `json:"scan_status"`
	ScanDate              time.Time            `json:"scan_date"`
	ScanError             string               `json:"scan_error"`
	SensitiveData         int                  `json:"sensitive_data"`
	Malware               int                  `json:"malware"`
	Disallowed            bool                 `json:"disallowed"`
	Whitelisted           bool                 `json:"whitelisted"`
	Blacklisted           bool                 `json:"blacklisted"`
	PermissionAuthor      string               `json:"permission_author"`
	PartialResults        bool                 `json:"partial_results"`
	NewerImageExists      bool                 `json:"newer_image_exists"`
	PendingDisallowed     bool                 `json:"pending_disallowed"`
	MicroenforcerDetected bool                 `json:"microenforcer_detected"`
	Running               bool                 `json:"is_running"`
	ScanHistory           []ScanHistoryFinding `json:"scan_history"`
}

type ScanHistoryFinding struct {
	Registry             string    `json:"registry"`
	Repository           string    `json:"repository"`
	Name                 string    `json:"name"`
	Tag                  string    `json:"tag"`
	Date                 time.Time `json:"date"`
	Error                string    `json:"error"`
	Digest               string    `json:"digest"`
	DockerID             string    `json:"docker_id"`
	ImagePulled          bool      `json:"image_pulled"`
	ImageCreationDate    time.Time `json:"image_creation_date"`
	SensitiveDataScanned bool      `json:"sensitive_data_scanned"`
	ExecutablesScanned   bool      `json:"executables_scanned"`
	MalwareScanned       bool      `json:"malware_scanned"`
	CritVulns            int       `json:"crit_vulns"`
	HighVulns            int       `json:"high_vulns"`
	MedVulns             int       `json:"med_vulns"`
	LowVulns             int       `json:"low_vulns"`
	NegVulns             int       `json:"neg_vulns"`
	SensitiveData        int       `json:"sensitive_data"`
	Malware              int       `json:"malware"`
	Disallowed           bool      `json:"disallowed"`
	PartialResults       bool      `json:"partial_results"`
}
