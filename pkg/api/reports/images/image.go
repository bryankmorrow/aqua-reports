package reports

import (
	"github.com/BryanKMorrow/aqua-sdk-go/types/images"
)

// Image contains the structure for a single image report
type Image struct {
	Risk            images.SingleResponse  `json:"risk"`
	Vulnerabilities images.Vulnerabilities `json:"vulnerabilities"`
	SensitiveData   images.Sensitive       `json:"sensitive_data"`
	Malware         images.Malware         `json:"smalware"`
	Response        ImageResponse          `json:"image_response"`
}

// ImageResponse for returning status of report creation
type ImageResponse struct {
	Name        string `json:"image"`
	Tag         string `json:"tag"`
	Registry    string `json:"registry"`
	URL         string `json:"url"`
	WriteStatus string `json:"write-status,omitempty"`
}
