package reports

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/BryanKMorrow/aqua-reports/src/system/aqua"
	"github.com/BryanKMorrow/aqua-reports/src/system/reports"
)

// Post - Take a list of images and get their risk
func Post(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	defer Track(RunningTime("Post"))
	log.Println("/reports/post route called")
	var imageList []ImageResponse
	var irList ImageResponseList
	var responseList []ImageResponse

	csp := aqua.NewCSP()
	csp.ConnectCSP()

	i := 1
	_ = json.NewDecoder(r.Body).Decode(&imageList)
	for _, image := range imageList {
		ir := csp.GetImageRisk(image.Registry, image.Name, image.Tag)
		vuln := csp.GetImageVulnerabilities(image.Registry, image.Name, image.Tag)
		sens := csp.GetImageSensitive(image.Registry, image.Name, image.Tag)
		malw := csp.GetImageMalware(image.Registry, image.Name, image.Tag)
		resp := reports.WriteHTMLReport(image.Name, image.Tag, ir, vuln, malw, sens)
		var response = ImageResponse{image.Name, image.Tag, image.Registry, resp}
		responseList = append(responseList, response)
		i++
	}
	irList.Count = i
	irList.Response = responseList
	json.NewEncoder(w).Encode(irList)
}
