package images

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
	"github.com/gorilla/mux"

	"github.com/BryanKMorrow/aqua-sdk-go/types/images"
)

// Image contains the structure for a single image report
type Image struct {
	Risk            images.SingleResponse  `json:"risk"`
	Vulnerabilities images.Vulnerabilities `json:"vulnerabilities"`
	SensitiveData   images.Sensitive       `json:"sensitive_data"`
	Malware         images.Malware         `json:"malware"`
	Response        reports.Response       `json:"response"`
}

// ImageHandler needs to handle the incoming request and execute the proper Image call
func ImageHandler(w http.ResponseWriter, r *http.Request) {
	var image Image
	// Get the registry, image and tag from the path parameters
	p := mux.Vars(r)
	str := p["image"]
	strings.TrimLeft(str, "/")
	strings.TrimRight(str, "/")
	split := strings.Split(str, "/")
	registry := split[0]
	tag := split[len(split)-1]
	var img string
	for i, s := range split {
		if i > 0 && i < len(split)-1 {
			if i == 1 {
				img = s
			} else {
				img = img + "/" + s
			}
		}
	}
	params := make(map[string]string)
	params["registry"] = registry
	params["image"] = img
	params["tag"] = tag
	reports.UnescapeURLQuery(params)
	queue := make(chan reports.Response)
	response := image.Get(params, queue)
	close(queue)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Get - single image risk report
// Param: http.ResponseWriter - writer to send back to requester
// Param: *http.Request - request
func (i *Image) Get(params map[string]string, queue chan reports.Response) reports.Response {
	defer reports.Track(reports.RunningTime("image.Get"))
	var err error
	//var remaining, total, next int

	// Get the request query parameters and unescape them
	reports.UnescapeURLQuery(params)
	// Get the client
	cli := reports.GetClient(i)
	// Get the Image Risk and verify the image exists
	i.Risk, err = cli.GetImage(params["registry"], params["image"], params["tag"])
	if err != nil {
		var response = reports.Response{
			Message: fmt.Sprintf("Scan Report for %s:%s in %s", params["registry"], params["image"], params["tag"]),
			URL:     "",
			Status:  "Image Not Found",
		}
		return response
	}
	// ignoring remaining, next, total for now
	i.Vulnerabilities, _, _, _ = cli.GetVulnerabilities(params["registry"], params["image"], params["tag"], 0, 1000, nil, nil)
	i.SensitiveData = cli.GetSensitive(params["registry"], params["image"], params["tag"])
	i.Malware = cli.GetMalware(params["registry"], params["image"], params["tag"])
	var response = reports.Response{
		Message: fmt.Sprintf("Scan Report for %s:%s in %s", params["image"], params["tag"], params["registry"]),
		URL:     "",
		Status:  "Write Successful",
	}
	queue <- response
	return response
}
