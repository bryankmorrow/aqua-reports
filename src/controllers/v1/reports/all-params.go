package reports

import (
	"log"
	"net/http"
	"net/url"
	"strconv"

	"github.com/BryanKMorrow/aqua-reports/src/system/aqua"
	"github.com/gorilla/mux"
)

// AllParams - This is the HTTP Handler to display the HTML Report and JSON output
func AllParams(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	encodedPagesize := params["pagesize"]
	ps, err := url.QueryUnescape(encodedPagesize)
	if err != nil {
		log.Println(err)
		return
	}
	pagesize, _ := strconv.Atoi(ps)

	encodedPage := params["page"]
	p, err := url.QueryUnescape(encodedPage)
	if err != nil {
		log.Println(err)
		return
	}
	page, _ := strconv.Atoi(p)

	csp := aqua.NewCSP()
	csp.ConnectCSP()

	list, _, repoCount, remain := csp.GetAllImages(pagesize, page)

	go CreateScanReport(csp, list, repoCount, remain, pagesize, page)

	w.Write([]byte("Creating reports for all image repositories. Please check the application log for status"))
	//json.NewEncoder(w).Encode(irList)
}
