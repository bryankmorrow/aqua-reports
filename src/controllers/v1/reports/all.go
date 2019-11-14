package reports

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/BryanKMorrow/aqua-reports/src/system/aqua"
	"github.com/BryanKMorrow/aqua-reports/src/system/reports"
)

// ImageResponseList for returning  all report status
type ImageResponseList struct {
	Count    int             `json:"count,omitempty"`
	Response []ImageResponse `json:"response"`
}

// ImageResponse for returning status of report creation
type ImageResponse struct {
	Name        string `json:"image"`
	Tag         string `json:"tag"`
	Registry    string `json:"registry"`
	WriteStatus string `json:"write-status,omitempty"`
}

// All - This is the HTTP Handler to display the HTML Report and JSON output
func All(w http.ResponseWriter, r *http.Request) {
	defer Track(RunningTime("/reports/all"))
	w.Header().Set("Content-Type", "application/json")
	var irList ImageResponseList
	var responseList []ImageResponse
	i := 1

	csp := aqua.NewCSP()
	csp.ConnectCSP()

	list := csp.GetAllImages("100", "1")

	for _, l := range list {
		for _, v := range l.Result {
			ir := csp.GetImageRisk(v.Registry, v.Repository, v.Tag)
			vuln := csp.GetImageVulnerabilities(v.Registry, v.Repository, v.Tag)
			sens := csp.GetImageSensitive(v.Registry, v.Repository, v.Tag)
			malw := csp.GetImageMalware(v.Registry, v.Repository, v.Tag)
			resp := reports.WriteHTMLReport(ir.Repository, ir.Tag, ir, vuln, malw, sens)
			var response = ImageResponse{v.Repository, v.Tag, v.Registry, resp}
			responseList = append(responseList, response)
			i++
		}
	}
	irList.Count = i
	irList.Response = responseList
	_ = json.NewEncoder(w).Encode(irList)
}

// RunningTime - Start the Timer
func RunningTime(s string) (string, time.Time) {
	log.Printf("Start:	%s route", s)
	return s, time.Now()
}

// Track - Stop the Timer
func Track(s string, startTime time.Time) {
	endTime := time.Now()
	log.Printf("End: %s route took %v", s, endTime.Sub(startTime))
}
