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
	Containers struct {
		Running      int `json:"running"`
		Unregistered int `json:"unregistered"`
	} `json:"containers"`
	Enforcers struct {
		Count int `json:"count"`
	} `json:"enforcers"`
	Images struct {
		Count    int `json:"count"`
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
		Ok       int `json:"ok"`
	} `json:"images"`
	Vulnerabilities struct {
		Count    int `json:"count"`
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
	} `json:"vulnerabilities"`
	Assurance struct {
		Count    int `json:"count"`
		Image    int `json:"image,omitempty"`
		Function int `json:"function,omitempty"`
		Host     int `json:"host,omitempty"`
		PCF      int `json:"pcf,omitempty"`
	} `json:"assurance"`
}

//Overview - Executive Dashboard
func Overview(w http.ResponseWriter, r *http.Request) {
	defer Track(RunningTime("Overview"))
	log.Println("/reports/overview route called")

	csp := aqua.NewCSP()
	csp.ConnectCSP()

	overview, enforcers := csp.GetExecutiveOverview()
	assurance := csp.AssuranceOverview()

	reports.WriteHTMLOverview(overview, enforcers)

	var response = OverviewResponse{}
	response.Containers.Running = overview.RunningContainers.Total
	response.Containers.Unregistered = overview.RunningContainers.Unregistered
	response.Enforcers.Count = enforcers.Count
	response.Images.Count = overview.RegistryCounts.Images.Total
	response.Images.Critical = overview.RegistryCounts.Images.Critical
	response.Images.High = overview.RegistryCounts.Images.High
	response.Images.Medium = overview.RegistryCounts.Images.Medium
	response.Images.Low = overview.RegistryCounts.Images.Low
	response.Images.Ok = overview.RegistryCounts.Images.Ok
	response.Vulnerabilities.Count = overview.RegistryCounts.Vulnerabilities.Total
	response.Vulnerabilities.Critical = overview.RegistryCounts.Vulnerabilities.Critical
	response.Vulnerabilities.High = overview.RegistryCounts.Vulnerabilities.High
	response.Vulnerabilities.Medium = overview.RegistryCounts.Vulnerabilities.Medium
	response.Vulnerabilities.Low = overview.RegistryCounts.Vulnerabilities.Low
	response.Assurance.Count = assurance.Count
	response.Assurance.Image = assurance.Image
	response.Assurance.Host = assurance.Host
	response.Assurance.Function = assurance.Function
	response.Assurance.PCF = assurance.PCF

	json.NewEncoder(w).Encode(response)
}
