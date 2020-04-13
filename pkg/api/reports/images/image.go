package images

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
	"github.com/gorilla/mux"

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

// Handler needs to handle the incoming request and execute the proper Image call
func Handler(w http.ResponseWriter, r *http.Request) {
	var image Image
	image.Get(w, r)
}

// Get - single image risk report
// Param: http.ResponseWriter - writer to send back to requester
// Param: *http.Request - request
func (i *Image) Get(w http.ResponseWriter, r *http.Request) {
	defer reports.Track(reports.RunningTime("image.Get"))
	var err error
	var remaining, total, next int
	w.Header().Set("Content-Type", "application/json")
	// Get the request query parameters and unescape them
	params := mux.Vars(r)
	reports.UnescapeURLQuery(params)
	// Get the client
	cli := reports.GetClient(i)
	// Get the Image Risk and verify the image exists
	i.Risk, err = cli.GetImage(params["registry"], params["image"], params["tag"])
	if err != nil {
		var response = ImageResponse{params["registry"], params["image"], params["tag"], "", "NOT FOUND"}
		json.NewEncoder(w).Encode(response)
	}
	i.Vulnerabilities, remaining, next, total = cli.GetVulnerabilities(params["registry"], params["image"], params["tag"], 0, 1000, nil, nil)
	log.Printf("Vulnerabilities: %d  Remaining: %d  Next Page: %d", total, remaining, next)
	i.SensitiveData = cli.GetSensitive(params["registry"], params["image"], params["tag"])
	i.Malware = cli.GetMalware(params["registry"], params["image"], params["tag"])
	var response = ImageResponse{params["registry"], params["image"], params["tag"], "nil", "nil"}
	json.NewEncoder(w).Encode(response)
}
