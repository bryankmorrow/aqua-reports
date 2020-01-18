package aqua

import (
	"encoding/json"
	"log"
	"os"

	"github.com/parnurzeal/gorequest"
)

// Mode determines if command-line or container
var Mode string

// URL points to an instance of Aqua CSP
var URL string

// User is the Aqua CSP user accessing the API
var User string

// Password is the password for the above user
var Password string

// NewCSP - initialize the CSP
func NewCSP() CSP {
	return CSP{}
}

// ConnectCSP - Connect to Aqua and return a JWT bearerToken (string)
func (csp *CSP) ConnectCSP() {
	if Mode == "cli" {
		csp.url = URL
		csp.user = User
		csp.password = Password
	} else {
		// Get Environment Parameters
		csp.url = os.Getenv("AQUA_URL")
		csp.user = os.Getenv("AQUA_USER")
		csp.password = os.Getenv("AQUA_PASSWORD")
	}

	request := gorequest.New()
	resp, body, errs := request.Post(csp.url + "/api/v1/login").Send(`{"id":"` + csp.user + `", "password":"` + csp.password + `"}`).End()

	if errs != nil {
		log.Printf("Failed connecting to Aqua CSP: %s \n  Status Code: %d", csp.url, resp.StatusCode)
	}

	if resp.StatusCode == 200 {
		var raw map[string]interface{}
		_ = json.Unmarshal([]byte(body), &raw)
		csp.token = raw["token"].(string)
	}
}

// GetAllImages - GET api/v2/repositories?filter=&include_totals=true&order_by=name&page=1&pagesize=100
func (csp *CSP) GetAllImages(pagesize, page int) ([]ImageList, int, int, int) {
	imageCount := 0
	var imageList []ImageList
	remaining, page, repos := csp.repositoryResult(pagesize, page)
	for _, result := range repos.Result {
		scanResult := csp.imageScanResult(result.Registry, result.Name, result.NumImages)
		imageList = append(imageList, scanResult)
		imageCount = imageCount + result.NumImages
	}

	return imageList, imageCount, repos.Count, remaining
}

// GetImageRisk - GET the risk API
func (csp *CSP) GetImageRisk(registry, repo, tag string) (ImageRisk, bool) {
	exists := true
	var ir = ImageRisk{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	events, body, errs := request.Clone().Get(csp.url + "/api/v2/images/" + registry + "/" + repo + "/" + tag).End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &ir)
		if err != nil {
			log.Println("func imageRisk: " + err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
	} else if events.StatusCode != 200 {
		log.Printf("%s/%s:%s not found in Aqua CSP.", registry, repo, tag)
		exists = false
	}

	return ir, exists
}

// GetImageVulnerabilities - GET the vulnerabilities API
func (csp *CSP) GetImageVulnerabilities(registry, repo, tag string) ImageVulnerabilities {
	var vuln = ImageVulnerabilities{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	events, body, errs := request.Clone().Get(csp.url + "/api/v2/images/" + registry + "/" + repo + "/" + tag + "/vulnerabilities?show_negligible=true&pagesize=1000").End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &vuln)
		if err != nil {
			log.Println("func imageVulnerabilities:" + err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
	}
	return vuln
}

// GetImageSensitive - GET the sensitive API for an image
func (csp *CSP) GetImageSensitive(registry, repo, tag string) Sensitive {
	var sensitive = Sensitive{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	events, body, errs := request.Clone().Get(csp.url + "/api/v2/images/" + registry + "/" +
		repo + "/" + tag + "/sensitive").End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &sensitive)
		if err != nil {
			log.Println("func imageSensitive: " + err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
	}
	return sensitive
}

// GetImageMalware - GET the malware API for an image
func (csp *CSP) GetImageMalware(registry, repo, tag string) Malware {
	var malware = Malware{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	events, body, errs := request.Clone().Get(csp.url + "/api/v2/images/" + registry + "/" +
		repo + "/" + tag + "/malware").End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &malware)
		if err != nil {
			log.Println("func imageMalware: " + err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
	}
	return malware
}

// GetExecutiveOverview - API call to get Aqua Dashboard information
func (csp *CSP) GetExecutiveOverview() (ExecutiveOverview, Enforcers, ResponseTrends, ResponseTrends, ResponseTrends) {
	var overview = ExecutiveOverview{}
	var enforcers = Enforcers{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	events, body, errs := request.Clone().Get(csp.url + "/api/v1/dashboard?registry=&hosts=&containers_app=").End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &overview)
		if err != nil {
			log.Println("func GetExecutiveOverview: " + err.Error())
		}
	}
	//Enforcers
	events, body, errs = request.Clone().Get(csp.url + "/api/v1/hosts?hosts=").End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &enforcers)
		if err != nil {
			log.Println("func GetExecutiveOverview->Enforcers: " + err.Error())
		}
	}
	containerTrends := csp.trendsResult("containers")
	imageTrends := csp.trendsResult("images")
	vulnTrends := csp.trendsResult("vulnerabilities")

	return overview, enforcers, imageTrends, vulnTrends, containerTrends
}

// AssuranceOverview gets the count of each Assurance policy type
func (csp *CSP) AssuranceOverview() ResponseAssurance {
	var assurance = PolicyAssurance{}
	var response = ResponseAssurance{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	events, body, errs := request.Clone().Get(csp.url + "/api/v2/assurance_policy?identifiers_only=true&order_by=name").End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &assurance)
		if err != nil {
			log.Println("func AssuranceOverview: " + err.Error())
		}
		response.Count = assurance.Count
		for _, policy := range assurance.Result {
			if policy.AssuranceType == "image" {
				response.Image++
			} else if policy.AssuranceType == "host" {
				response.Host++
			} else if policy.AssuranceType == "function" {
				response.Function++
			} else {
				response.PCF++
			}
		}
	}
	return response
}
