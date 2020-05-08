package vulnerabilities

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
	"github.com/BryanKMorrow/aqua-reports/pkg/types/vulnerabilities"
	"github.com/BryanKMorrow/aqua-sdk-go/types/images"
)

type VulnFinding vulnerabilities.VulnFinding
type Vulnerability vulnerabilities.Vulnerability

// Handler needs to handle the incoming request and execute the finding report generation
// Param: http.ResponseWriter - writer to send back to requester
// Param: *http.Request - request
func Handler(w http.ResponseWriter, r *http.Request) {
	var vulnFinding VulnFinding
	params := make(map[string]string)
	params["path"] = r.Host
	queue := make(chan reports.Response)
	response := vulnFinding.Get(params, queue)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Get - generate the finding report
// Param: map[string]string - Map of request parameters
// Param: chan reports.Response - Channel that accepts the JSON response from each finding (TODO)
// Return: reports.Response - the Json response sent to the requester
func (v *VulnFinding) Get(params map[string]string, queue chan reports.Response) reports.Response {
	defer reports.Track(reports.RunningTime("top.Get"))
	var vl []images.Vulnerability
	var il []images.Image
	// Connect to the Client
	cli := reports.GetClient(v)
	// Get All Vulnerabilities
	detail, remaining, next, total := cli.GetRiskVulnerabilities(1, 1000, nil)
	log.Printf("Vulnerabilities Remaining: %d  Next: %d  Total: %d", remaining, next, total)
	vl = append(vl, detail.Result...)
	for remaining > 0 {
		detail, remaining, next, total = cli.GetRiskVulnerabilities(next, 1000, nil)
		log.Printf("Vulnerabilities Remaining: %d  Next: %d  Total: %d", remaining, next, total)
		vl = append(vl, detail.Result...)
	}
	// Get All Images
	images, remaining, next, total := cli.GetAllImages(0, 1000, nil, nil)
	log.Printf("Images Remaining: %d  Next: %d  Total: %d", remaining, next, total)
	il = append(il, images.Result...)
	for remaining > 0 {
		images, remaining, next, total = cli.GetAllImages(0, 1000, nil, nil)
		log.Printf("Images Remaining: %d  Next: %d  Total: %d", remaining, next, total)
		il = append(il, images.Result...)
	}
	// Loop through each vulnerability and map images to Vuln
	vulns := []Vulnerability{}
	for _, v := range vl {
		var vuln Vulnerability
		i, found := Find(vulns, v.Name)
		if !found {
			vuln.Name = v.Name
			vuln.Vulnerability = v
			ok, img := vuln.MapVulnerabilityToImage(il)
			if ok {
				vuln.Images = append(vuln.Images, img)
				vulns = append(vulns, vuln)
			}
		} else {
			ok, img := vulns[i].MapVulnerabilityToImage(il)
			if ok {
				vulns[i].Images = append(vulns[i].Images, img)
			}
		}
	}
	sort.Slice(vulns, func(i, j int) bool {
		if len(vulns[i].Images) > len(vulns[j].Images) {
			return true
		}
		if len(vulns[i].Images) < len(vulns[j].Images) {
			return false
		}
		return vulns[i].Name < vulns[j].Name
	})
	log.Println("Top 25 Vulnerabilities by Image Count")
	for _, q := range vulns[:25] {
		log.Printf("Vulnerability: %s  Image Count: %d", q.Name, len(q.Images))
	}
	fileName := "test.html"
	var response = reports.Response{
		Message: "Top Vulnerabilities Findings Report",
		URL:     "http://" + params["path"] + "/" + fileName,
		Status:  "Write Successful",
	}
	return response
}

func (v *Vulnerability) MapVulnerabilityToImage(il []images.Image) (bool, images.Image) {
	for _, image := range il {
		if (v.Vulnerability.ImageName == image.Name) && (v.Vulnerability.Registry == image.Registry) {
			return true, image
		}
	}
	return false, images.Image{}
}

func Find(vulns []Vulnerability, name string) (int, bool) {
	for i, vuln := range vulns {
		if vuln.Name == name {
			return i, true
		}
	}
	return -1, false
}
