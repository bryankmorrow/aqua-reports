package vulnerabilities

import (
	"bufio"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
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
	vulns := []vulnerabilities.Vulnerability{}
	for _, v := range vl {
		var vuln vulnerabilities.Vulnerability
		i, found := Find(vulns, v.Name)
		if !found {
			vuln.Name = v.Name
			vuln.Vulnerability = v
			ok, img := MapVulnerabilityToImage(vuln, il)
			if ok {
				vuln.Images = append(vuln.Images, img)
				vulns = append(vulns, vuln)
			}
		} else {
			ok, img := MapVulnerabilityToImage(vulns[i], il)
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

func MapVulnerabilityToImage(v vulnerabilities.Vulnerability, il []images.Image) (bool, images.Image) {
	for _, image := range il {
		if (v.Vulnerability.ImageName == image.Name) && (v.Vulnerability.Registry == image.Registry) {
			return true, image
		}
	}
	return false, images.Image{}
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
            <td style="color: #000;">{{vuln.vulnerability.aqua_score}}</td>
            <td style="color: #000;text-align:left;width:150px;max-width:200px;">{{vuln.vulnerability.publish_date}}</td>
            <td style="color: #000;text-align:left;width:150px;max-width:200px;">{{vuln.vulnerability.modification_date}}</td>
            <td style="color: #000;">{{vuln.vulnerability.resource.type}}</td>
            <td style="color: #000;text-align:left;width:150px;max-width:350px;"><span v-if="vuln.vulnerability.resource.type == 'package'">{{vuln.vulnerability.resource.name}}</span>
                <span v-else>{{getPath(index)}} {{fileName}}</span>
            </td>
            <td style="color: #000;text-align:left;width:150px;max-width:350px;">{{vuln.vulnerability.resource.version}}</td>
        </tr>
        </tbody>
        </table>
        </div>
        </div>
            
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
                    activeIndex: 0,
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

                    },
                    sort(collection, column, event){
                      if(column == 'name' || column == 'publish_date' || column == 'severity'){
                          this[collection].sort((a, b) => a[column].localeCompare(b[column]))
                      }else{
                          this[collection].sort((a, b) => b[column] - a[column]);
                      }
                    },
                    getPath: function(index){
                        str = this.vuln_finding[index].vulnerability.resource.path.split("/")
                        this.fileName = str[str.length -1]
                        console.log(this.fileName)
                    },
                },
                computed:{
        		    current_vuln: function(){
                          if(this.pageLoad){
                              return "Overall"
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
