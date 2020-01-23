package reports

import (
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
	URL         string `json:"url"`
	WriteStatus string `json:"write-status,omitempty"`
}

// All - This is the HTTP Handler to display the HTML Report and JSON output
func All(w http.ResponseWriter, r *http.Request) {

	csp := aqua.NewCSP()
	csp.ConnectCSP()
	pagesize := 100
	page := 1

	list, _, repoCount, remain := csp.GetAllImages(pagesize, page)

	go CreateScanReport(csp, list, repoCount, remain, pagesize, page)
	w.Write([]byte("Creating reports for all image repositories. Please check the application log for status"))
}

// CreateScanReport - iterates through the slice of ImageList
// Call this using a go routine so it can parse all images
// when greater than the pagesize
func CreateScanReport(csp aqua.CSP, list []aqua.ImageList, repoCount, remain, pagesize, page int) {
	defer Track(RunningTime("All Reports"))
	i := 1
	for _, l := range list {
		for _, v := range l.Result {
			ir, exists := csp.GetImageRisk(v.Registry, v.Repository, v.Tag)
			if exists {
				vuln := csp.GetImageVulnerabilities(v.Registry, v.Repository, v.Tag)
				sens := csp.GetImageSensitive(v.Registry, v.Repository, v.Tag)
				malw := csp.GetImageMalware(v.Registry, v.Repository, v.Tag)
				_, _ = reports.WriteHTMLReport(ir.Repository, ir.Tag, ir, vuln, malw, sens)
				i++
			}
		}
	}
	if remain > 0 {
		page++
		log.Printf("Calling another round of repositories - Pagesize: %d - Next Page: %d", pagesize, page)
		list, _, repoCount, remain = csp.GetAllImages(pagesize, page)
		go CreateScanReport(csp, list, repoCount, remain, pagesize, page)
	}
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
