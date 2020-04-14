package findings

import (
	"encoding/json"
	"fmt"
	"github.com/BryanKMorrow/aqua-reports/pkg/types/findings"
	"github.com/BryanKMorrow/aqua-reports/pkg/types/images"
	"github.com/BryanKMorrow/aqua-reports/pkg/types/registries"
	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/BryanKMorrow/aqua-sdk-go/types/containers"
	imagessdk "github.com/BryanKMorrow/aqua-sdk-go/types/images"
	"log"
	"net/http"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
)

type Finding findings.Finding

// FindingHandler needs to handle the incoming request and execute the finding report generation
// Param: http.ResponseWriter - writer to send back to requester
// Param: *http.Request - request
func FindingHandler(w http.ResponseWriter, r *http.Request) {
	var finding Finding
	response := finding.Get(nil, nil)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Get - generate the finding report
// Param: map[string]string - Map of request parameters
// Param: chan reports.Response - Channel that accepts the JSON response from each finding (TODO)
// Return: reports.Response - the Json response sent to the requester
func (f *Finding) Get(params map[string]string, queue chan reports.Response) reports.Response {
	defer reports.Track(reports.RunningTime("findings.Get"))
	var registryList []registries.RegistryFinding
	// Connect to the Client
	cli := reports.GetClient(f)
	// Get Registries
	rl := cli.GetRegistries()
	for _, reg := range rl {
		var r registries.RegistryFinding
		r.Name = reg.Name
		r.Description = reg.Description
		r.DetectedType = reg.DetectedType
		r.Author = reg.Author
		r.URL = reg.URL
		r.Type = reg.Type
		r.Lastupdate = reg.Lastupdate
		r.Username = reg.Username
		params := make(map[string]string)
		params["registry"] = reg.Name
		params["fix_availability"] = "true"
		il, _, _, _ := cli.GetAllImages(0, 1000, params, nil)
		cl, _, _, _ := cli.GetContainers(0, 1000, nil)
		r.ImageCount = il.Count
		var imageList []images.ImageFinding
		for _, i := range il.Result {
			r.CritVulns = r.CritVulns + i.CritVulns
			r.HighVulns = r.HighVulns + i.HighVulns
			r.MedVulns = r.MedVulns + i.MedVulns
			r.LowVulns = r.LowVulns + i.LowVulns
			r.TotalVulns = r.TotalVulns + i.VulnsFound
			r.SensitiveData = r.SensitiveData + r.SensitiveData
			r.Malware = r.Malware + r.Malware
			var img images.ImageFinding
			img.Registry = i.Registry
			img.Name = i.Name
			img.VulnsFound = i.VulnsFound
			img.CritVulns = i.CritVulns
			img.HighVulns = i.HighVulns
			img.MedVulns = i.MedVulns
			img.LowVulns = i.LowVulns
			img.NegVulns = i.NegVulns
			img.FixableVulns = 0
			img.Repository = i.Repository
			img.Tag = i.Tag
			img.Created = i.Created
			img.Author = i.Author
			img.Digest = i.Digest
			img.Size = i.Size
			img.Os = i.Os
			img.OsVersion = i.OsVersion
			img.ScanStatus = i.ScanStatus
			img.ScanDate = i.ScanDate
			img.ScanError = i.ScanError
			img.SensitiveData = i.SensitiveData
			img.Malware = i.Malware
			img.Disallowed = i.Disallowed
			img.Whitelisted = i.Whitelisted
			img.Blacklisted = i.Blacklisted
			img.PartialResults = i.PartialResults
			img.NewerImageExists = i.NewerImageExists
			img.PendingDisallowed = i.PendingDisallowed
			img.MicroenforcerDetected = i.MicroenforcerDetected
			img.FixableVulns = GetFixableVulnCount(cli, img)
			img.Running = MapContainerToImage(cl, img)
			hl := GetScanHistory(cli, img.Registry, img.Repository, img.Tag)
			img.ScanHistory = hl
			imageList = append(imageList, img)
		}
		r.Images = imageList
		registryList = append(registryList, r)
	}
	var response = reports.Response{
		Message: "Findings Report for all Registries",
		URL:     "",
		Status:  "Write Successful",
	}
	data, _ := json.Marshal(registryList)
	log.Println(string(data))
	return response
}

func GetFixableVulnCount(cli *client.Client, i images.ImageFinding) int {
	var count, remaining, next int
	var vulns imagessdk.Vulnerabilities
	params := make(map[string]string)
	params["show_negligible"] = "true"
	params["hide_base_image"] = "false"
	vulns, remaining, _, next = cli.GetVulnerabilities(i.Registry, i.Repository, i.Tag, 0, 1000, params, nil)
	for _, vuln := range vulns.Result {
		if vuln.FixVersion != "" {
			count++
		}
	}
	for remaining > 0 {
		vulns, r, _, n := cli.GetVulnerabilities(i.Registry, i.Repository, i.Tag, next, 1000, params, nil)
		for _, vuln := range vulns.Result {
			if vuln.FixVersion != "" {
				count++
			}
		}
		remaining = r
		next = n
	}
	return count
}

func MapContainerToImage(cl containers.Containers, i images.ImageFinding) bool {
	var isRunning bool
	for _, cont := range cl.Result {
		if cont.ImageID == i.Digest {
			isRunning = true
		}
	}
	return isRunning
}

// GetScanHistory calls the aqua-sdk-go GetScanHistory call
// Param: cli: *client.Client - Aqua client from aqua-sdk-go
// Param: registry: string - Name of the Aqua configured registry
// Param: image: string - Name of the image to retrieve scan history
// Param: tag: string - Image tag
// Return: []ScanHistoryFinding - slice of ScanHistoryFinding struct for the image
func GetScanHistory(cli *client.Client, registry, image, tag string) []images.ScanHistoryFinding {
	var histories []images.ScanHistoryFinding
	history, err := cli.GetScanHistory(registry, image, tag)
	if err != nil {
		log.Println("error while retrieving image scan history: " + err.Error())
	}
	for _, scan := range history.Result {
		h := images.ScanHistoryFinding{
			Registry:             registry,
			Repository:           image,
			Name:                 fmt.Sprintf("%s:%s", image, tag),
			Tag:                  tag,
			Date:                 scan.Date,
			Error:                scan.Error,
			Digest:               scan.Digest,
			DockerID:             scan.DockerID,
			ImagePulled:          scan.ImagePulled,
			ImageCreationDate:    scan.ImageCreationDate,
			SensitiveDataScanned: scan.SensitiveDataScanned,
			ExecutablesScanned:   scan.ExecutablesScanned,
			MalwareScanned:       scan.MalwareScanned,
			CritVulns:            scan.CritVulns,
			HighVulns:            scan.HighVulns,
			MedVulns:             scan.MedVulns,
			LowVulns:             scan.LowVulns,
			NegVulns:             scan.NegVulns,
			SensitiveData:        scan.SensitiveData,
			Malware:              scan.Malware,
			Disallowed:           scan.Disallowed,
			PartialResults:       scan.PartialResults,
		}
		histories = append(histories, h)
	}
	return histories
}
