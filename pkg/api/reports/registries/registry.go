package registries

import (
	"encoding/json"
	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
	"github.com/BryanKMorrow/aqua-reports/pkg/types/registries"

	"net/http"

	"github.com/gorilla/mux"
)

type Registry registries.RegistryFinding

// RegistriesHandler needs to handle the incoming request and execute the proper registry calls
func RegistriesHandler(w http.ResponseWriter, r *http.Request) {
	var registry Registry
	params := mux.Vars(r)
	queue := make(chan reports.Response)
	response := registry.Get(params, queue)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Get - Calls the client and retrieves all the Registry details
// Param: map[string]string - Map of request parameters
// Param: chan reports.Response - Channel that accepts the JSON response from each registry
// Return: reports.Response - the Json response sent to the requester
func (r *Registry) Get(params map[string]string, queue chan reports.Response) reports.Response {
	defer reports.Track(reports.RunningTime("registries.Get"))
	var rl []*registries.RegistryFinding
	reports.UnescapeURLQuery(params)
	cli := reports.GetClient(r)
	reg := cli.GetRegistries()
	for _, registry := range reg {
		r := new(registries.RegistryFinding)
		r.Name = registry.Name
		r.Description = registry.Description
		r.DetectedType = registry.DetectedType
		r.Author = registry.Author
		r.URL = registry.URL
		r.Type = registry.Type
		r.Lastupdate = registry.Lastupdate
		r.Username = registry.Username
		rl = append(rl, r)
	}
	status, _ := json.Marshal(rl)
	var response = reports.Response{
		Message: "Got all registries",
		URL:     "",
		Status:  string(status),
	}
	return response
}
