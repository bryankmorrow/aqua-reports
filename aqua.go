package main

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/parnurzeal/gorequest"
)

// Aqua Settings Structure
type Aqua struct {
	url      string
	user     string
	password string
	token    string
}

//Connect to Aqua and return a JWT bearerToken (string)
func connectCSP() string {
	// Get Environment Parameters
	var csp Aqua
	csp.url = os.Getenv("AQUA_URL")
	csp.user = os.Getenv("AQUA_USER")
	csp.password = os.Getenv("AQUA_PASSWORD")

	var bearerToken string
	request := gorequest.New()
	resp, body, errs := request.Post(csp.url + "/api/v1/login").Send(`{"id":"` + csp.user + `", "password":"` + csp.password + `"}`).End()

	if errs != nil {
		log.Printf("Failed connecting to Aqua CSP: %s \n  Status Code: %d", csp.url, resp.StatusCode)
	}

	if resp.StatusCode == 200 {
		var raw map[string]interface{}
		json.Unmarshal([]byte(body), &raw)
		bearerToken = raw["token"].(string)
	}
	//log.Println(bearerToken)
	return bearerToken
}

// IMAGES

// AllImages comes from allImages data return
type AllImages struct {
	Count    int `json:"count"`
	Page     int `json:"page"`
	Pagesize int `json:"pagesize"`
	Result   []struct {
		Name                   string `json:"name"`
		Registry               string `json:"registry"`
		Author                 string `json:"author"`
		Policy                 string `json:"policy"`
		DynamicProfiling       bool   `json:"dynamic_profiling"`
		NumImages              int    `json:"num_images"`
		NumDisallowed          int    `json:"num_disallowed"`
		NumFailed              int    `json:"num_failed"`
		HighVulns              int    `json:"high_vulns"`
		MedVulns               int    `json:"med_vulns"`
		LowVulns               int    `json:"low_vulns"`
		NegVulns               int    `json:"neg_vulns"`
		SensitiveData          int    `json:"sensitive_data"`
		Malware                int    `json:"malware"`
		TrustedBaseCount       int    `json:"trusted_base_count"`
		WhitelistedImagesCount int    `json:"whitelisted_images_count"`
		IsDefaultPolicy        bool   `json:"is_default_policy"`
	} `json:"result"`
	Query struct {
		Orderby string      `json:"orderby"`
		Scopes  interface{} `json:"Scopes"`
	} `json:"query"`
	MoreData int `json:"more_data"`
}

// ImageList comes from the looped repository query after AllImages
type ImageList struct {
	Count    int `json:"count"`
	Page     int `json:"page"`
	Pagesize int `json:"pagesize"`
	Result   []struct {
		Registry         string        `json:"registry"`
		Name             string        `json:"name"`
		VulnsFound       int           `json:"vulns_found"`
		HighVulns        int           `json:"high_vulns"`
		MedVulns         int           `json:"med_vulns"`
		LowVulns         int           `json:"low_vulns"`
		NegVulns         int           `json:"neg_vulns"`
		Repository       string        `json:"repository"`
		Tag              string        `json:"tag"`
		Created          time.Time     `json:"created"`
		Author           string        `json:"author"`
		Digest           string        `json:"digest"`
		Size             int           `json:"size"`
		Labels           interface{}   `json:"labels"`
		Os               string        `json:"os"`
		OsVersion        string        `json:"os_version"`
		ScanStatus       string        `json:"scan_status"`
		ScanDate         time.Time     `json:"scan_date"`
		ScanError        string        `json:"scan_error"`
		SensitiveData    int           `json:"sensitive_data"`
		Malware          int           `json:"malware"`
		Disallowed       bool          `json:"disallowed"`
		Whitelisted      bool          `json:"whitelisted"`
		Blacklisted      bool          `json:"blacklisted"`
		PolicyFailures   []interface{} `json:"policy_failures"`
		PartialResults   bool          `json:"partial_results"`
		NewerImageExists bool          `json:"newer_image_exists"`
		AssuranceResults struct {
			Disallowed      bool        `json:"disallowed"`
			ChecksPerformed interface{} `json:"checks_performed"`
		} `json:"assurance_results"`
		PendingDisallowed     bool `json:"pending_disallowed"`
		MicroenforcerDetected bool `json:"microenforcer_detected"`
	} `json:"result"`
}

//ImageRisk comes from the base image call
type ImageRisk struct {
	Registry         string      `json:"registry"`
	Name             string      `json:"name"`
	VulnsFound       int         `json:"vulns_found"`
	HighVulns        int         `json:"high_vulns"`
	MedVulns         int         `json:"med_vulns"`
	LowVulns         int         `json:"low_vulns"`
	NegVulns         int         `json:"neg_vulns"`
	Repository       string      `json:"repository"`
	Tag              string      `json:"tag"`
	Created          time.Time   `json:"created"`
	Author           string      `json:"author"`
	Digest           string      `json:"digest"`
	Size             int         `json:"size"`
	Labels           interface{} `json:"labels"`
	Os               string      `json:"os"`
	OsVersion        string      `json:"os_version"`
	ScanStatus       string      `json:"scan_status"`
	ScanDate         time.Time   `json:"scan_date"`
	ScanError        string      `json:"scan_error"`
	SensitiveData    int         `json:"sensitive_data"`
	Malware          int         `json:"malware"`
	Disallowed       bool        `json:"disallowed"`
	Whitelisted      bool        `json:"whitelisted"`
	Blacklisted      bool        `json:"blacklisted"`
	PartialResults   bool        `json:"partial_results"`
	NewerImageExists bool        `json:"newer_image_exists"`
	Metadata         struct {
		DockerID      string      `json:"docker_id"`
		Parent        string      `json:"parent"`
		RepoDigests   []string    `json:"repo_digests"`
		Comment       string      `json:"comment"`
		Created       time.Time   `json:"created"`
		DockerVersion string      `json:"docker_version"`
		Author        string      `json:"author"`
		Architecture  string      `json:"architecture"`
		Os            string      `json:"os"`
		OsVersion     string      `json:"os_version"`
		Size          int         `json:"size"`
		VirtualSize   int         `json:"virtual_size"`
		DefaultUser   string      `json:"default_user"`
		Env           []string    `json:"env"`
		DockerLabels  interface{} `json:"docker_labels"`
	} `json:"metadata"`
	History []struct {
		ID        string `json:"id"`
		Size      int    `json:"size"`
		Comment   string `json:"comment"`
		Created   string `json:"created"`
		CreatedBy string `json:"created_by"`
	} `json:"history"`
	AssuranceResults struct {
		Disallowed      bool `json:"disallowed"`
		ChecksPerformed []struct {
			PolicyName    string `json:"policy_name"`
			AssuranceType string `json:"assurance_type"`
			Failed        bool   `json:"failed"`
			Blocking      bool   `json:"blocking"`
			Control       string `json:"control"`
		} `json:"checks_performed"`
	} `json:"assurance_results"`
	ScanWarnings          []interface{} `json:"scan_warnings"`
	PendingDisallowed     bool          `json:"pending_disallowed"`
	MicroenforcerDetected bool          `json:"microenforcer_detected"`
}

//ImageVulnerabilities is derived from singular image vulnerability query
type ImageVulnerabilities struct {
	Count    int `json:"count"`
	Page     int `json:"page"`
	Pagesize int `json:"pagesize"`
	Result   []struct {
		Registry                  string      `json:"registry"`
		ImageRepositoryName       string      `json:"image_repository_name"`
		ReferencedVulnerabilities interface{} `json:"referenced_vulnerabilities"`
		Resource                  struct {
			Type     string   `json:"type"`
			Format   string   `json:"format"`
			Path     string   `json:"path"`
			Name     string   `json:"name"`
			Version  string   `json:"version"`
			Arch     string   `json:"arch"`
			Cpe      string   `json:"cpe"`
			Licenses []string `json:"licenses"`
			Hash     string   `json:"hash"`
		} `json:"resource"`
		Name                   string      `json:"name"`
		Description            string      `json:"description"`
		PublishDate            string      `json:"publish_date"`
		ModificationDate       string      `json:"modification_date"`
		VendorSeverity         string      `json:"vendor_severity"`
		VendorCvss2Score       float64     `json:"vendor_cvss2_score"`
		VendorCvss2Vectors     string      `json:"vendor_cvss2_vectors"`
		VendorCvss3Severity    string      `json:"vendor_cvss3_severity"`
		VendorCvss3Score       float64     `json:"vendor_cvss3_score"`
		VendorCvss3Vectors     string      `json:"vendor_cvss3_vectors"`
		VendorStatement        string      `json:"vendor_statement"`
		VendorURL              string      `json:"vendor_url"`
		NvdSeverity            string      `json:"nvd_severity"`
		NvdCvss2Score          float64     `json:"nvd_cvss2_score"`
		NvdCvss2Vectors        string      `json:"nvd_cvss2_vectors"`
		NvdCvss3Severity       string      `json:"nvd_cvss3_severity"`
		NvdCvss3Score          float64     `json:"nvd_cvss3_score"`
		NvdCvss3Vectors        string      `json:"nvd_cvss3_vectors"`
		NvdURL                 string      `json:"nvd_url"`
		FixVersion             string      `json:"fix_version"`
		Solution               string      `json:"solution"`
		Classification         string      `json:"classification"`
		QualysIds              interface{} `json:"qualys_ids"`
		AquaScore              float64     `json:"aqua_score"`
		AquaSeverity           string      `json:"aqua_severity"`
		AquaVectors            string      `json:"aqua_vectors"`
		AquaScoringSystem      string      `json:"aqua_scoring_system"`
		VPatchAppliedBy        string      `json:"v_patch_applied_by"`
		VPatchAppliedOn        string      `json:"v_patch_applied_on"`
		VPatchRevertedBy       string      `json:"v_patch_reverted_by"`
		VPatchRevertedOn       string      `json:"v_patch_reverted_on"`
		VPatchEnforcedBy       string      `json:"v_patch_enforced_by"`
		VPatchEnforcedOn       string      `json:"v_patch_enforced_on"`
		VPatchStatus           string      `json:"v_patch_status"`
		AcknowledgedDate       time.Time   `json:"acknowledged_date"`
		AckScope               string      `json:"ack_scope"`
		AckComment             string      `json:"ack_comment"`
		AckAuthor              string      `json:"ack_author"`
		VPatchPolicyName       string      `json:"v_patch_policy_name"`
		VPatchPolicyEnforce    bool        `json:"v_patch_policy_enforce"`
		AuditEventsCount       int         `json:"audit_events_count"`
		BlockEventsCount       int         `json:"block_events_count"`
		ImageWorkloadInfo      interface{} `json:"image_workload_info"`
		BaseImageVulnerability bool        `json:"base_image_vulnerability"`
		BaseImageName          string      `json:"base_image_name"`
	} `json:"result"`
}

//Malware struct
type Malware struct {
	Count    int `json:"count"`
	Page     int `json:"page"`
	Pagesize int `json:"pagesize"`
	Result   []struct {
		Malware          string    `json:"malware"`
		Hash             string    `json:"hash"`
		Path             string    `json:"path"`
		Paths            []string  `json:"paths"`
		Acknowledged     bool      `json:"acknowledged"`
		AcknowledgeDate  time.Time `json:"acknowledge_date"`
		AcknowledgeScope string    `json:"acknowledge_scope"`
	} `json:"result"`
}

//Sensitive struct
type Sensitive struct {
	Count    int `json:"count"`
	Page     int `json:"page"`
	Pagesize int `json:"pagesize"`
	Result   []struct {
		Type             string    `json:"type"`
		Path             string    `json:"path"`
		Hash             string    `json:"hash"`
		Filename         string    `json:"filename"`
		Acknowledged     bool      `json:"acknowledged"`
		AcknowledgeDate  time.Time `json:"acknowledge_date"`
		AcknowledgeScope string    `json:"acknowledge_scope"`
	} `json:"result"`
}

//Get all Images (Images Tab in Aqua UI)
//GET api/v2/repositories?filter=&include_totals=true&order_by=name&page=1&pagesize=100
func allImages(csp Aqua) []ImageList {
	var data = AllImages{}
	var imageList = []ImageList{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	events, body, errs := request.Clone().Get(csp.url + "/api/v2/repositories?filter=&include_totals=true&order_by=name").End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &data)
		if err != nil {
			log.Println(err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
		for _, result := range data.Result {
			var list = ImageList{}
			events, body, errs = request.Clone().Get(csp.url + "/api/v2/images?name=" + result.Name + "&page_size=" +
				strconv.Itoa(result.NumImages)).End()
			if errs != nil {
				log.Println(events.StatusCode)
			}
			if events.StatusCode == 200 {
				err := json.Unmarshal([]byte(body), &list)
				if err != nil {
					log.Println(err.Error())
					//json: Unmarshal(non-pointer main.Request)
				}
				imageList = append(imageList, list)
			}
		}
	}
	return imageList
}

func imageRisk(csp Aqua, registry, repo, tag string) ImageRisk {
	var ir = ImageRisk{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	events, body, errs := request.Clone().Get(csp.url + "/api/v2/images/" + registry + "/" +
		repo + "/" + tag).End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &ir)
		if err != nil {
			log.Println(err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
	}
	return ir
}

func imageVulnerabilities(csp Aqua, registry, repo, tag string) ImageVulnerabilities {
	var vuln = ImageVulnerabilities{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	events, body, errs := request.Clone().Get(csp.url + "/api/v2/images/" + registry + "/" +
		repo + "/" + tag + "/vulnerabilities?show_negligible=true&pagesize=1000").End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &vuln)
		if err != nil {
			log.Println(err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
	}
	return vuln
}

func imageSensitive(csp Aqua, registry, repo, tag string) Sensitive {
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
			log.Println(err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
	}
	return sensitive
}

func imageMalware(csp Aqua, registry, repo, tag string) Malware {
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
			log.Println(err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
	}
	return malware
}
