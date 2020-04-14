package reports

import (
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/BryanKMorrow/aqua-sdk-go/client"
)

// Mode determines if command-line or container
var Mode string

// URL points to an instance of Aqua CSP
var URL string

// User is the Aqua CSP user accessing the API
var User string

// Password is the password for the above user
var Password string

// Reports represents all reports
type Reports interface {
	Get(params map[string]string, queue chan Response) Response
}

// Response for returning JSON to browser per request
type Response struct {
	Message string `json:"message"`
	URL     string `json:"url,omitempty"`
	Status  string `json:"status"`
}

// GetClient returns the aqua-sdk-go client to interact with CSP
func GetClient(r Reports) *client.Client {
	// Get the Aqua CSP connection parameters from Environment Variables
	if Mode != "cli" {
		URL = os.Getenv("AQUA_URL")
		User = os.Getenv("AQUA_USER")
		Password = os.Getenv("AQUA_PASSWORD")
	}

	// Create the client and get the JWT token for API call authorization
	cli := client.NewClient(URL, User, Password)
	connected := cli.GetAuthToken()
	if !connected {
		log.Fatalln("Failed to retrieve JWT Authorization Token")
	}
	return cli
}

// UnescapeURLQuery - uses the url package to unescape the incoming query parameters
// Param: map[string]string - params are received from the incoming http request
func UnescapeURLQuery(params map[string]string) {
	for k, v := range params {
		value, err := url.QueryUnescape(v)
		if err != nil {
			log.Println("error while Un-escaping Query Parameter: ", err)
			return
		}
		params[k] = value
	}
}

// CreateImageFile - the HTML File for the scan report
func CreateImageFile(registry, image, tag string) string {
	fileName := registry + "-" + strings.Replace(image, "/", "_", -1) + "-" + tag + ".html"
	fileName = strings.ToLower(fileName)
	fileName = strings.Replace(fileName, " ", "", -1)
	err := os.Remove("reports/" + fileName)
	if err != nil {
		log.Println(err)
	}
	return "reports/" + fileName
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
