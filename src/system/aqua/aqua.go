package aqua

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/parnurzeal/gorequest"
)

// CSP Settings Structure
type CSP struct {
	url      string
	user     string
	password string
	token    string
}

// AllImages struct comes from allImages data return
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
			PolicyName           string   `json:"policy_name"`
			AssuranceType        string   `json:"assurance_type"`
			Failed               bool     `json:"failed"`
			Blocking             bool     `json:"blocking"`
			Control              string   `json:"control"`
			SensitiveDataFound   int32    `json:"sensitive_data_found,omitempty"`
			MaxSeverityAllowed   string   `json:"max_severity_allowed,omitempty"`
			MaxSeverityFound     string   `json:"max_severity_found,omitempty"`
			MalwareFound         int64    `json:"malware_found,omitempty"`
			RootUserFound        bool     `json:"root_user_found,omitempty"`
			BlacklistedCvesFound []string `json:"blacklisted_cves_found,omitempty"`
			CustomChecksFailed   []struct {
				ScriptName string `json:"script_name"`
				ScriptType string `json:"script_type"`
				ExitCode   int    `json:"exit_code"`
				Output     string `json:"output"`
			} `json:"custom_checks_failed,omitempty"`
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

// ExecutiveOverview struct
type ExecutiveOverview struct {
	Filter struct {
		Application string `json:"application"`
		Registry    string `json:"registry"`
		Hosts       string `json:"hosts"`
	} `json:"filter"`
	RunningContainers struct {
		Total        int `json:"total"`
		High         int `json:"high"`
		Medium       int `json:"medium"`
		Low          int `json:"low"`
		Ok           int `json:"ok"`
		Unregistered int `json:"unregistered"`
	} `json:"running_containers"`
	RegistryCounts struct {
		Images struct {
			Total  int `json:"total"`
			High   int `json:"high"`
			Medium int `json:"medium"`
			Low    int `json:"low"`
			Ok     int `json:"ok"`
		} `json:"images"`
		ImagesTrends    interface{} `json:"images_trends"`
		Vulnerabilities struct {
			Total  int `json:"total"`
			High   int `json:"high"`
			Medium int `json:"medium"`
			Low    int `json:"low"`
			Ok     int `json:"ok"`
		} `json:"vulnerabilities"`
		CvesTrends interface{} `json:"cves_trends"`
	} `json:"registry_counts"`
	Hosts struct {
		Total             int         `json:"total"`
		DisconnectedCount int         `json:"disconnected_count"`
		Hosts             interface{} `json:"hosts"`
	} `json:"hosts"`
	Alerts []struct {
		ID           int    `json:"id"`
		Time         int    `json:"time"`
		Type         string `json:"type"`
		User         string `json:"user"`
		Image        string `json:"image"`
		Imagehash    string `json:"imagehash"`
		Container    string `json:"container"`
		Containerid  string `json:"containerid"`
		Host         string `json:"host"`
		Hostid       string `json:"hostid"`
		Category     string `json:"category"`
		Result       int    `json:"result"`
		UserResponse string `json:"user_response"`
		Data         string `json:"data"`
	} `json:"alerts"`
	AuditTickers []struct {
		ID          int    `json:"id"`
		Time        int    `json:"time"`
		Type        string `json:"type"`
		User        string `json:"user"`
		Action      string `json:"action"`
		Image       string `json:"image"`
		Imagehash   string `json:"imagehash"`
		Container   string `json:"container"`
		Containerid string `json:"containerid"`
		Host        string `json:"host"`
		Hostid      string `json:"hostid"`
		Category    string `json:"category"`
		Result      int    `json:"result"`
		Data        string `json:"data"`
	} `json:"audit_tickers"`
}

// Enforcers struct
type Enforcers struct {
	Count    int `json:"count"`
	Page     int `json:"page"`
	Pagesize int `json:"pagesize"`
	Result   []struct {
		ProjectID          int         `json:"project_id"`
		ID                 string      `json:"id"`
		Logicalname        string      `json:"logicalname"`
		Description        string      `json:"description"`
		Type               string      `json:"type"`
		Version            string      `json:"version"`
		Commit             string      `json:"commit"`
		Hostname           string      `json:"hostname"`
		ShortHostname      string      `json:"short_hostname"`
		Address            string      `json:"address"`
		PublicAddress      string      `json:"public_address"`
		Addresses          interface{} `json:"addresses"`
		Lastupdate         int         `json:"lastupdate"`
		Status             string      `json:"status"`
		Serverid           string      `json:"serverid"`
		ServerName         string      `json:"server_name"`
		DockerVersion      string      `json:"docker_version"`
		HostOs             string      `json:"host_os"`
		IsWindows          bool        `json:"is_windows"`
		HighVulns          int         `json:"high_vulns"`
		MedVulns           int         `json:"med_vulns"`
		LowVulns           int         `json:"low_vulns"`
		NegVulns           int         `json:"neg_vulns"`
		VulnsFound         int         `json:"vulns_found"`
		LastVulnScan       int         `json:"last_vuln_scan"`
		DisplayName        string      `json:"display_name"`
		Compliant          bool        `json:"compliant"`
		Machineid          string      `json:"machineid"`
		ClusterID          int         `json:"cluster_id"`
		Hostlabels         interface{} `json:"hostlabels"`
		Gateways           []string    `json:"gateways"`
		Token              string      `json:"token"`
		Enforce            bool        `json:"enforce"`
		Scan               bool        `json:"scan"`
		TotalPass          int         `json:"total_pass"`
		TotalWarn          int         `json:"total_warn"`
		HostKernelVersion  string      `json:"host_kernel_version"`
		KernelModuleLoaded bool        `json:"kernel_module_loaded"`
		RuntimeProtection  int         `json:"runtime_protection"`
		DockerInfo         struct {
		} `json:"docker_info,omitempty"`
		ContainerActivityProtection bool `json:"container_activity_protection"`
		NetworkProtection           bool `json:"network_protection"`
		UserAccessControl           bool `json:"user_access_control"`
		SyncHostImages              bool `json:"sync_host_images"`
		ImageAssurance              bool `json:"image_assurance"`
		HostProtection              bool `json:"host_protection"`
		Orchestrator                struct {
			Type   string `json:"type"`
			Master bool   `json:"master"`
		} `json:"orchestrator,omitempty"`
		AuditAll          bool        `json:"audit_all"`
		AuditSuccessLogin bool        `json:"audit_success_login"`
		AuditFailedLogin  bool        `json:"audit_failed_login"`
		BatchInstallID    int         `json:"batch_install_id"`
		SaveBatchID       int         `json:"save_batch_id"`
		BatchInstallName  string      `json:"batch_install_name"`
		SyscallEnabled    bool        `json:"syscall_enabled"`
		RuntimeType       string      `json:"runtime_type"`
		InterceptionMode  string      `json:"interception_mode"`
		AquaDigest        string      `json:"aqua_digest"`
		ContainerID       string      `json:"container_id"`
		Secrets           interface{} `json:"secrets"`
	} `json:"result"`
	Query struct {
		IdentifiersOnly bool   `json:"identifiers_only"`
		Status          string `json:"status"`
		ImageName       string `json:"image_name"`
		ImageID         string `json:"image_id"`
		ServerID        string `json:"server_id"`
		BatchName       string `json:"batch_name"`
		Compliant       string `json:"compliant"`
		Address         string `json:"address"`
		Cve             string `json:"cve"`
		ConfigFileName  string `json:"config_file_name"`
	} `json:"query"`
}

// NewCSP - initialize the CSP
func NewCSP() CSP {
	return CSP{}
}

// ConnectCSP - Connect to Aqua and return a JWT bearerToken (string)
func (csp *CSP) ConnectCSP() {
	// Get Environment Parameters
	csp.url = os.Getenv("AQUA_URL")
	csp.user = os.Getenv("AQUA_USER")
	csp.password = os.Getenv("AQUA_PASSWORD")

	request := gorequest.New()
	resp, body, errs := request.Post(csp.url + "/api/v1/login").Send(`{"id":"` + csp.user + `", "password":"` + csp.password + `"}`).End()

	if errs != nil {
		log.Printf("Failed connecting to Aqua CSP: %s \n  Status Code: %d", csp.url, resp.StatusCode)
	}

	if resp.StatusCode == 200 {
		var raw map[string]interface{}
		json.Unmarshal([]byte(body), &raw)
		csp.token = raw["token"].(string)
	}
}

// GetAllImages - GET api/v2/repositories?filter=&include_totals=true&order_by=name&page=1&pagesize=100
func (csp *CSP) GetAllImages() []ImageList {
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

		if data.Count <= 50 {
			for _, result := range data.Result {
				var list = ImageList{}
				events, body, errs = request.Clone().Get(csp.url + "/api/v2/images?name=" + result.Name + "&page_size=" + strconv.Itoa(result.NumImages)).End()
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
		} else {
			pages := getRepositoryCount(data.Count)
			for i := 1; i <= pages; i++ {
				events, body, errs := request.Clone().Get(csp.url + "/api/v2/repositories?filter=&include_totals=true&order_by=name&page=" + strconv.Itoa(i)).End()
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
						events, body, errs = request.Clone().Get(csp.url + "/api/v2/images?name=" + result.Name + "&page_size=" + strconv.Itoa(result.NumImages)).End()
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
			}
		}

	}
	return imageList
}

// GetImageRisk - GET the risk API
func (csp *CSP) GetImageRisk(registry, repo, tag string) ImageRisk {
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
	}
	return ir
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
func (csp *CSP) GetExecutiveOverview() (ExecutiveOverview, Enforcers) {
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
	return overview, enforcers
}

func getRepositoryCount(count int) int {
	pages := 0
	switch {
	case count <= 50:
		pages = 1
	case count > 50 && count <= 100:
		pages = 2
	case count > 100 && count <= 150:
		pages = 3
	}
	return pages
}
