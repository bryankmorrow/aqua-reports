package images

import (
	"time"
)

type TagHistory struct {
	Name     string `json:"name"`
	Registry string `json:"registry"`
	Tags     []Tag  `json:"tags"`
}

type Tag struct {
	Name       string    `json:"tag"`
	Created    time.Time `json:"created"`
	VulnsFound int       `json:"vulns_found"`
	CritVulns  int       `json:"crit_vulns"`
	HighVulns  int       `json:"high_vulns"`
	MedVulns   int       `json:"med_vulns"`
	LowVulns   int       `json:"low_vulns"`
	NegVulns   int       `json:"neg_vulns"`
}
