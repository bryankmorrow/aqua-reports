package reports

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/BryanKMorrow/aqua-reports/src/system/aqua"
	"github.com/BryanKMorrow/aqua-reports/src/system/reports"
	"github.com/gorilla/mux"
)

// AllParams - This is the HTTP Handler to display the HTML Report and JSON output
func AllParams(w http.ResponseWriter, r *http.Request) {
	defer Track(RunningTime("/reports/all/pagesize/page"))
	w.Header().Set("Content-Type", "application/json")
	var irList ImageResponseList
	var responseList []ImageResponse
	i := 1

	params := mux.Vars(r)
	encodedPagesize := params["pagesize"]
	pagesize, err := url.QueryUnescape(encodedPagesize)
	if err != nil {
		log.Println(err)
		return
	}
	encodedPage := params["page"]
	page, err := url.QueryUnescape(encodedPage)
	if err != nil {
		log.Println(err)
		return
	}

	csp := aqua.NewCSP()
	csp.ConnectCSP()

	list, _, _ := csp.GetAllImages(pagesize, page)

	for _, l := range list {
		for _, v := range l.Result {
			ir := csp.GetImageRisk(v.Registry, v.Repository, v.Tag)
			vuln := csp.GetImageVulnerabilities(v.Registry, v.Repository, v.Tag)
			sens := csp.GetImageSensitive(v.Registry, v.Repository, v.Tag)
			malw := csp.GetImageMalware(v.Registry, v.Repository, v.Tag)
			resp, path := reports.WriteHTMLReport(ir.Repository, ir.Tag, ir, vuln, malw, sens)
			url := fmt.Sprintf("http://%s/reports/%s", r.Host, path)
			var response = ImageResponse{v.Repository, v.Tag, v.Registry, url, resp}
			responseList = append(responseList, response)
			i++
		}
	}
	irList.Count = i
	irList.Response = responseList
	json.NewEncoder(w).Encode(irList)
}
