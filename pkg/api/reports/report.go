package reports

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/BryanKMorrow/aqua-sdk-go/client"
)

// Reports represents all reports
type Reports interface {
	Get(w http.ResponseWriter, r *http.Request)
}

// GetClient returns the aqua-sdk-go client to interact with CSP
func GetClient(r Reports) *client.Client {
	// Get the Aqua CSP connection parameters from Environment Variables
	url := os.Getenv("AQUA_URL")
	user := os.Getenv("AQUA_USER")
	password := os.Getenv("AQUA_PASSWORD")

	// Create the client and get the JWT token for API call authorization
	cli := client.NewClient(url, user, password)
	connected := cli.GetAuthToken()
	if !connected {
		log.Fatalln("Failed to retrieve JWT Authorization Token")
	}
	return cli
}

// RunningTime - Start the Report Timer
func RunningTime(r Reports) time.Time {
	return time.Now()
}

// Track - Stop the Report Timer
func Track(r Reports, startTime time.Time) time.Duration {
	endTime := time.Now()
	return endTime.Sub(startTime)
}
