package scans

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
)

// Webhook stores the incoming scan result details
type Webhook struct {
	Image    string `json:"image"`
	Registry string `json:"registry"`
}

// Handler needs to handle the incoming scan result webook
func Handler(w http.ResponseWriter, r *http.Request) {
	response := Get(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Get receives the incoming scan result and maps to outgoing Webhook
func Get(r *http.Request) Webhook {
	defer reports.Track(reports.RunningTime("scans.Get"))
	var webhook Webhook
	log.Println(r.Body)
	err := json.NewDecoder(r.Body).Decode(&webhook)
	if err != nil {
		log.Println("error decoding body, ", err)
	}
	return webhook
}
