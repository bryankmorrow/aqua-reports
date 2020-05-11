package vulnerabilities

import (
	"bufio"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/BryanKMorrow/aqua-sdk-go/client"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
	reportImages "github.com/BryanKMorrow/aqua-reports/pkg/types/images"
	"github.com/BryanKMorrow/aqua-reports/pkg/types/vulnerabilities"
	"github.com/BryanKMorrow/aqua-sdk-go/types/images"
)

type VulnFinding vulnerabilities.VulnFinding

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
	detail, remaining, next, _ := cli.GetRiskVulnerabilities(1, 1000, nil)
	vl = append(vl, detail.Result...)
	for remaining > 0 {
		detail, remaining, next, _ = cli.GetRiskVulnerabilities(next, 1000, nil)
		vl = append(vl, detail.Result...)
	}
	// Get All Images
	images, remaining, next, _ := cli.GetAllImages(1, 1000, nil, nil)
	il = append(il, images.Result...)
	for remaining > 0 {
		images, remaining, next, _ = cli.GetAllImages(next, 1000, nil, nil)
		il = append(il, images.Result...)
	}
	// Loop through each Image and get vulnerabilities
	ifl := ConvertImageToFinding(cli, il)

	// Loop through each vulnerability and map images to Vuln
	vulns := []vulnerabilities.Vulnerability{}
	for _, v := range vl {
		var vuln vulnerabilities.Vulnerability
		i, found := Find(vulns, v.Name)
		if !found {
			vuln.Name = v.Name
			vuln.Vulnerability = v
			ok, img := MapImageToVulnerability(vuln, ifl)
			if ok {
				vuln.Images = append(vuln.Images, img)
				vulns = append(vulns, vuln)
			}
		} else {
			ok, img := MapImageToVulnerability(vulns[i], ifl)
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
	top := UpdateImageCounts(vulns[:25])
	topData, _ := json.Marshal(top)
	v.Template = GetTemplate(string(topData))
	v.Vulnerabilities = top
	fileName := reports.CreateFindingsFile("vuln_findings")
	w, err := os.OpenFile(fileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	writer := bufio.NewWriter(w)
	writer.WriteString(v.Template)
	writer.Flush()
	w.Close()
	var response = reports.Response{
		Message: "Top Vulnerabilities Findings Report",
		URL:     "http://" + params["path"] + "/" + fileName,
		Status:  "Write Successful",
	}
	return response
}

func ConvertImageToFinding(cli *client.Client, il []images.Image) []reportImages.ImageFinding {
	var ifl []reportImages.ImageFinding
	for _, i := range il {
		var vil []images.Vulnerability
		var vfi []string
		vuln, remaining, next, _ := cli.GetVulnerabilities(i.Registry, i.Repository, i.Tag, 0, 1000, nil, nil)
		vil = append(vil, vuln.Result...)
		for remaining > 0 {
			vuln, remaining, _, _ = cli.GetVulnerabilities(i.Registry, i.Repository, i.Tag, next, 1000, nil, nil)
			vil = append(vil, vuln.Result...)
		}
		for _, v := range vil {
			vfi = append(vfi, v.Name)
		}
		ivf := reportImages.ImageFinding{
			Registry:        i.Registry,
			Name:            i.Name,
			VulnsFound:      i.VulnsFound,
			CritVulns:       i.CritVulns,
			HighVulns:       i.HighVulns,
			MedVulns:        i.MedVulns,
			LowVulns:        i.LowVulns,
			NegVulns:        i.NegVulns,
			RegistryType:    i.RegistryType,
			Repository:      i.Repository,
			Tag:             i.Tag,
			Created:         i.Created,
			ScanDate:        i.ScanDate,
			SensitiveData:   i.SensitiveData,
			Malware:         i.Malware,
			Disallowed:      i.Disallowed,
			Vulnerabilities: vfi,
		}
		ifl = append(ifl, ivf)
	}
	return ifl
}

func MapImageToVulnerability(v vulnerabilities.Vulnerability, ivl []reportImages.ImageFinding) (bool, reportImages.ImageFinding) {
	for _, iv := range ivl {
		for _, vuln := range iv.Vulnerabilities {
			if v.Name == vuln {
				_, found := FindImageInVuln(v.Images, iv.Name)
				if !found {
					return true, iv
				}
			}
		}
	}
	return false, reportImages.ImageFinding{}
}

func UpdateImageCounts(vulns []vulnerabilities.Vulnerability) []vulnerabilities.Vulnerability {
	var vl []vulnerabilities.Vulnerability
	for _, v := range vulns {
		v.Count = len(v.Images)
		vl = append(vl, v)
	}
	return vl
}

func Find(vulns []vulnerabilities.Vulnerability, name string) (int, bool) {
	for i, vuln := range vulns {
		if vuln.Name == name {
			return i, true
		}
	}
	return -1, false
}

func FindImageInVuln(ivf []reportImages.ImageFinding, name string) (int, bool) {
	for index, i := range ivf {
		if i.Name == name {
			return index, true
		}
	}
	return -1, false
}

// GetTemplate retrieves the final HTML to be written
// Param: topData: string - The 'vulnerabilities: []' data to be replaced
// Return: string - the findings HTML string
func GetTemplate(topData string) string {
	template := `
		
		<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8"/>
			<link rel="icon" href="https://community-aqua-reports.s3.amazonaws.com/favicon.ico">
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@100;400;500;900&display=swap" rel="stylesheet">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css">
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
        <style>
			body{font-family: 'Roboto','Open Sans', sans-serif; font-size: 14px;}
			hr{ color: #6a6a6a;}
			table{border: none;}
			td { text-align: center;height:25px;width:75px;color:#fff;white-space: pre-wrap;}
			tr{margin-bottom: 10px;}
			th {border: none; width:50px; text-align: center; white-space: pre-wrap;}
			h1{ font-weight: bold; margin-left: -10px;}
			h3{font-weight: 600; padding-top: 35px;}
			h5{font-weight: 600; padding-top: 15px; font-size: 16px;}
			[v-cloak] { display:none; }
			a:link, a:visited, a:hover, a:active {color: #000; text-decoration: none; }
			.truncate { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color:#000; text-align: left; padding-right: 10px; }
			.highlightme { background-color:#EFEFEF; }
			.badge-dark{background-color: #820040;}
			.badge-warning{background-color: #FF8E2A;}
			.badge-danger{background-color: #D90000;}
			.badge-primary{background-color:#357ABD;}
			.badge-secondary{background-color: #27A744}
			.hide2{visibility:hidden;}
        </style>
        </head>
        <body>

        <div class="container" id="app" v-cloak>
        <div class="row">
            <div class="col-md-6"><h1 style="margin-top: 50px;">Aqua Top Vulnerability Report</h1><span style="font-size: 9px">*Note: low and negligible vulnerabilities reflected in total but not presented.</span></div>
            <!-- <div class="col-md-6 text-right"><img src="https://community-aqua-reports.s3.amazonaws.com/aqua.png" height="150px" width="300px" style="padding-bottom: 20px;"></div> -->
        </div>

        <div class="row" style="margin-top: -40px;">
        <div class="col-12">
        <h3>Vulnerabilities</h3>
        <table style="margin-top: 15px; width: 100%">
        <thead>
        <th @click="sort('vuln_finding', 'name')" style="text-align: left;">Name</th>
        <th @click="sort('vuln_finding', 'count')">Images Count</th>
        <th @click="sort('vuln_finding', 'vulnerability.aqua_severity')">Severity</th>
        <th @click="sort('vuln_finding', 'vulnerability.aqua_score')" style="text-align: left; width: auto"><a href="#">Score</a></th>
        <th @click="sort('vuln_finding', 'vulnerability.publish_date')"><a href="#">Publish Date</a></th>
        <th @click="sort('vuln_finding', 'vulnerability.modification_date')"><a href="#">Modification Date</a></th>
        <th @click="sort('vuln_finding', 'vulnerability.resource.type')"><a href="#">Package Type</a></th>
        <th @click="sort('vuln_finding', 'vulnerability.resource.name')"><a href="#">Package Name</a></th>
        <th @click="sort('vuln_finding', 'vulnerability.resource.version')"><a href="#">Package Version</a></th>

        </thead>
        <tr v-for="(vuln, index) in vuln_finding" :key="index">
            <td class="truncate" @click="vuln_images(index)" style="text-align:left;width:100px;max-width:200px;"><span :class="{'highlightme': index == activeVuln && !pageLoad}">{{ vuln.name }}</span><i v-if="activeVuln == index && !pageLoad" class="fas fa-long-arrow-alt-left"></i></td>
            <td style="color: #000;">{{vuln.count}}</td>
			<td style="color: #000;"><span v-if="vuln.vulnerability.aqua_severity == 'medium'" class="badge badge-warning">{{ vuln.vulnerability.aqua_severity }}</span>
                <span v-else-if="vuln.vulnerability.aqua_severity == 'low'" class="badge badge-secondary">{{ vuln.vulnerability.aqua_severity }}</span>
                <span v-else-if="vuln.vulnerability.aqua_severity == 'critical'" class="badge badge-dark">{{ vuln.vulnerability.aqua_severity }}</span>
                <span v-else-if="vuln.vulnerability.aqua_severity == 'high'" class="badge badge-danger">{{ vuln.vulnerability.aqua_severity }}</span>
                <span v-else-if="vuln.vulnerability.aqua_severity == 'negligible'" class="badge badge-primary">{{ vuln.vulnerability.aqua_severity }}</span>
            </td>
            <td style="color: #000;text-align:left;">  {{vuln.vulnerability.aqua_score}}</td>
            <td style="color: #000;width:100px;max-width:150px;">{{vuln.vulnerability.publish_date}}</td>
            <td style="color: #000;width:100px;max-width:150px;">{{vuln.vulnerability.modification_date}}</td>
            <td style="color: #000;width:100px;">{{vuln.vulnerability.resource.type}}</td>
            <td style="color: #000;width:150px;max-width:350px;"><span v-if="vuln.vulnerability.resource.type == 'package'">{{vuln.vulnerability.resource.name}}</span>
                <span v-else>{{getPath(index)}} {{fileName}}</span>
            </td>
            <td style="color: #000;width:150px;max-width:350px;">{{vuln.vulnerability.resource.version}}</td>
        </tr>
        </tbody>
        </table>
        </div>
        </div>

		<div class="row">
                <div class="col-12">

                    <h3>{{current_vuln}} Vulnerable Images</h3>
                    <table style="margin-top: 15px;width: 100%">
                        <thead>
                        <th @click="sort('vuln_finding.images', 'name', $event)" style="text-align: left;">Name</th>
                        <th @click="sort('vuln_finding.images','registry')" style="text-align: left;"><a href="#">Registry</a></th>
                        <th @click="sort('vuln_finding.images','vulns_found')"><a href="#">Total Vulns</a></th>
                        <th @click="sort('vuln_finding.images','crit_vulns')"><a href="#">Critical</a></th>
                        <th @click="sort('vuln_finding.images','high_vulns')"><a href="#">High</a></th>
                        <th @click="sort('vuln_finding.images','med_vulns')"><a href="#">Medium</a></th>
                        <th @click="sort('vuln_finding.images','malware')"><a href="#">Malware</a></th>
                        <th @click="sort('vuln_finding.images','sensitive_data')"><a href="#">Sensitive</a></th>
                        </thead>
                        <tr v-for="(image, index) in vuln_finding[activeVuln].images" :key="index">
                            <td class="truncate" style="max-width: 350px;">{{ image.name }}</td>
                            <td style="color: #000; text-align: left;">{{image.registry}}</td>
                            <td><span class="badge badge-primary">{{image.vulns_found}}</span></td>
                            <td><span class="badge badge-dark">{{ image.crit_vulns }}</span></td>
                            <td><span class="badge badge-danger">{{ image.high_vulns }}</span></td>
                            <td><span class="badge badge-warning">{{ image.med_vulns }}</span></td>
                            <td><span class="badge badge-light">{{ image.malware }}</span></td>
                            <td><span class="badge badge-light">{{ image.sensitive_data }}</span></td>
                        </tr>
                        </tbody>
                    </table>

                </div><!-- end col-md-12 -->
            </div><!-- end row -->
            
        </div><!-- end app -->

        <script src="https://cdn.jsdelivr.net/npm/vue/dist/vue.js"></script>
        <script src="https://kit.fontawesome.com/27e233ddae.js" crossorigin="anonymous"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.24.0/moment-with-locales.min.js"></script>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/axios/0.19.0/axios.min.js"></script>

        <script>
            
            var poc = new Vue({
        		el: '#app',
        		data: { 
					vuln_finding: [],
                    activeVuln: 0,
                    pageLoad: false,
					fileName: "",
                },
                 mounted: function (){
                     document.onreadystatechange = () => {
                        if (document.readyState == "complete") {
                            this.pageLoad = true;
                        }
                     }
                },
                methods: {
        		    vuln_images(index){
        		        this.pageLoad = false;
        		        this.activeVuln = index;
                        this.activeImage = this.vuln_finding[index].images[0];

                    },
                    sort(collection, column, event){
                      if(column == 'name' || column == 'vulns_found' || column == 'severity'){
                          this[collection].sort((a, b) => a[column].localeCompare(b[column]))
                      }else{
                          this[collection].sort((a, b) => b[column] - a[column]);
                      }
                    },
                    getPath: function(index){
                        str = this.vuln_finding[index].vulnerability.resource.path.split("/")
                        this.fileName = str[str.length -1]
                    },
                },
                computed:{
                    current_vuln: function(){
                        if(this.pageLoad){
                            return this.vuln_finding[0].name
                        }else {
                            return this.vuln_finding[this.activeVuln].name
                        }
                    },
                },
                filters: {
                  spacing: function (value) {
                    if(value < 10) {
                        return " " + value;
                    }else{
                        return "" + value
                    }
                  },
                }
        	});
        </script>
        </body>
        </html>
	`
	response := strings.Replace(template, "vuln_finding: []", "vuln_finding: "+topData, -1)
	return response
}
