package reports

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/BryanKMorrow/aqua-reports/src/system/aqua"
	"github.com/BryanKMorrow/aqua-reports/src/system/reports"
)

// OverviewResponse for returning status of report creation
type OverviewResponse struct {
	RunningContainers      int `json:"running_containers"`
	UnregisteredContainers int `json:"unregistered_containers"`
}

//Overview - Executive Dashboard
func Overview(w http.ResponseWriter, r *http.Request) {
	defer Track(RunningTime("Overview"))
	log.Println("/reports/overview route called")

	csp := aqua.NewCSP()
	csp.ConnectCSP()

	overview, enforcers := csp.GetExecutiveOverview()

	reports.WriteHTMLOverview(overview, enforcers)

	var response = OverviewResponse{overview.RunningContainers.Total, overview.RunningContainers.Unregistered}

	json.NewEncoder(w).Encode(response)
}
