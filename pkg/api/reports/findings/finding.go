package findings

import (
	"bufio"
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
	"os"
	"sort"
	"strings"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
)

type Finding findings.Finding

// FindingHandler needs to handle the incoming request and execute the finding report generation
// Param: http.ResponseWriter - writer to send back to requester
// Param: *http.Request - request
func FindingHandler(w http.ResponseWriter, r *http.Request) {
	var finding Finding
	params := make(map[string]string)
	params["path"] = r.Host
	response := finding.Get(params, nil)
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
	cl, _, _, _ := cli.GetContainers(0, 1000, nil)
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
			// Sort the scan history
			sort.Slice(hl, func(i, j int) bool {
				return hl[i].Date.Before(hl[j].Date)
			})
			img.ScanHistory = hl
			imageList = append(imageList, img)
		}
		r.Images = imageList
		registryList = append(registryList, r)
	}
	// Get the top 10 images by vulnerability count
	var top []images.ImageFinding
	il, _, _, _ := cli.GetAllImages(0, 1000, nil, nil)
	for _, i := range il.Result {
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
		// Sort the scan history
		sort.Slice(hl, func(i, j int) bool {
			return hl[i].Date.Before(hl[j].Date)
		})
		img.ScanHistory = hl
		top = append(top, img)
	}
	//Sort Top
	sort.Slice(top, func(i, j int) bool {
		if top[i].VulnsFound > top[j].VulnsFound {
			return true
		}
		if top[i].VulnsFound < top[j].VulnsFound {
			return false
		}
		return top[i].Name < top[j].Name
	})
	registryData, _ := json.Marshal(registryList)
	topImages, _ := json.Marshal(top[:10])
	template := GetTemplate(string(registryData), string(topImages))
	fileName := reports.CreateFindingsFile()
	w, err := os.OpenFile(fileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	writer := bufio.NewWriter(w)
	writer.WriteString(template)
	writer.Flush()
	w.Close()
	var response = reports.Response{
		Message: "Findings Report for all Registries",
		URL:     "http://" + params["path"] + "/" + fileName,
		Status:  "Write Successful",
	}
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

func GetTemplate(regData, topData string) string {
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
            <div class="col-md-6"><h1 style="margin-top: 50px;">Aqua Interactive Findings Report</h1><span style="font-size: 9px">*Note: low and negligible vulnerabilities reflected in total but not presented.</span></div>
            <!-- <div class="col-md-6 text-right"><img src="https://community-aqua-reports.s3.amazonaws.com/aqua.png" height="150px" width="300px" style="padding-bottom: 20px;"></div> -->
        </div>

        <div class="row" style="margin-top: -40px;">
        <div class="col-12">
        <h3>Registries</h3>
        <table style="margin-top: 15px; width: 100%">
        <thead>
        <th @click="sort('registries', 'name')" style="text-align: left;">Name</th>
        <th @click="sort('registries', 'type')">Type</th>
        <th @click="sort('registries', 'prefix')" style="text-align: left; width: auto"><a href="#">Prefix</a></th>
        <th @click="sort('registries', 'image_count')"><a href="#">Images</a></th>

        <th @click="sort('registries', 'total_vulns')"><a href="#">Total Vulns</a></th>
        <th @click="sort('registries', 'crit_vulns')"><a href="#">Critical</a></th>
        <th @click="sort('registries', 'high_vulns')"><a href="#">High</a></th>
        <th @click="sort('registries', 'med_vulns')"><a href="#">Medium</a></th>
        <th @click="sort('registries', 'malware')"><a href="#">Malware</a></th>
        <th @click="sort('registries', 'sensitive_data')"><a href="#">Sensitive</a></th>

        </thead>
        <tr v-for="(registry, index) in registries" :key="index">
            <td class="truncate" @click="registry_images(index)" style="text-align: left;width:275px;max-width: 350px;"><span :class="{'highlightme': index == activeRegistry && !pageLoad}">{{ registry.name }}</span><i v-if="activeRegistry == index && !pageLoad" class="fas fa-long-arrow-alt-left"></i></td>
            <td style="color: #000;"><i v-html="type(index)"></i></td>
            <td class="truncate" style="color: #000; text-align: left; width:100px;max-width: 100px;">{{registry.url | url }}</td>
            <td><span class="badge badge-secondary">{{registry.image_count}}</span></td>
            <td><span class="badge badge-primary">{{registry.total_vulns}}</span></td>
            <td><span class="badge badge-dark">{{registry.crit_vulns}}</span></td>
            <td><span class="badge badge-danger">{{registry.high_vulns}}</span></td>
            <td><span class="badge badge-warning">{{registry.med_vulns}}</span></td>
            <td><span class="badge badge-light">{{registry.malware}}</span></td>
            <td><span class="badge badge-light">{{registry.sensitive_data}}</span></td>
        </tr>
        </tbody>
        </table>
        </div>
        </div>

        <div class="row">
        <div class="col-12">

        <h3>{{current_registry}} Top Vulnerable Images</h3>
        <table style="margin-top: 15px;width: 100%">
        <thead>
            <th @click="sort('images', 'name', $event)" style="text-align: left;">Name</th>
            <th @click="sort('images','registry')" style="text-align: left;"><a href="#">Registry</a></th>
            <th @click="sort('images','is_running')"><a href="#">Running</a></th>
            <th @click="sort('images','vulns_found')"><a href="#">Total Vulns</a></th>
            <th @click="sort('images','crit_vulns')"><a href="#">Critical</a></th>
            <th @click="sort('images','high_vulns')"><a href="#">High</a></th>
            <th @click="sort('images','med_vulns')"><a href="#">Medium</a></th>
            <th @click="sort('images','fixable_vulns')"><a href="#">Vendor Fix</a></th>
            <th @click="sort('images','malware')"><a href="#">Malware</a></th>
            <th @click="sort('images','sensitive_data')"><a href="#">Sensitive</a></th>
        </thead>
        <tr v-for="(image, index) in images" :key="index">
            <td class="truncate" @click="scan_history(index)" style="max-width: 350px;"><span :class="{'highlightme': activeImage.name == image.name}">{{ image.name }}</span><i v-if="activeImage.name == image.name" class="fas fa-long-arrow-alt-left"></i></td>
            <td style="color: #000; text-align: left;">{{image.registry}}</td>
            <td style="color: #000;">{{image.is_running}}</td>
            <td><span class="badge badge-primary">{{image.vulns_found}}</span></td>
            <td><span class="badge badge-dark">{{ image.crit_vulns }}</span></td>
            <td><span class="badge badge-danger">{{ image.high_vulns }}</span></td>
            <td><span class="badge badge-warning">{{ image.med_vulns }}</span></td>
            <td><span style="color: #000;">{{ image.fixable_vulns }}</span></td>
            <td><span class="badge badge-light">{{ image.malware }}</span></td>
            <td><span class="badge badge-light">{{ image.sensitive_data }}</span></td>
        </tr>
        </tbody>
        </table>

        </div><!-- end col-md-12 -->
        </div><!-- end row -->

        <div class="row">
        <div class="col-12">
        <h5 style=" margin-top: 40px;">{{scanTitle}}</h5>
        <div id="chart_div" :class="{'hide2': !showLineChart}" style="height: 350px; margin-top: 0px;width: 100%;"></div>
        </div><!-- end col-12 -->
        </div><!-- end row -->
        </div><!-- end app -->

        <script src="https://cdn.jsdelivr.net/npm/vue/dist/vue.js"></script>
        <script src="https://kit.fontawesome.com/27e233ddae.js" crossorigin="anonymous"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.24.0/moment-with-locales.min.js"></script>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/axios/0.19.0/axios.min.js"></script>
        <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>


        <script>
            google.charts.load('current', {'packages':['corechart']});
            google.charts.setOnLoadCallback(drawImageChart);

            function drawImageChart(image, scan_history) {
                var data = google.visualization.arrayToDataTable(scan_history);
                 var options = {
                    vAxis: { viewWindow:{ min: 0, } },
                    colors: ['#820040', '#D90000', '#FF8E2A'],
                     pointSize: 1,
                     pointVisible: true,
                     curveType: 'function',
                     legend: {position: 'in'},
                     width: "100%",
                     chartArea: { width: "95%"}
                }

                var chart = new google.visualization.LineChart(document.getElementById('chart_div'));
                chart.draw(data, options);
            }


            var poc = new Vue({
        		el: '#app',
        		data: { 
					registries: [],
					images: [],
                    activeIndex: 0,
                    activeRegistry: 0,
                    pageLoad: false,
                    showLineChart: true,
                    activeImage: "",
                },
                 mounted: function (){
                     document.onreadystatechange = () => {
                        if (document.readyState == "complete") {
                            this.activeImage = this.images[0];
                            this.scan_history(0);
                            this.pageLoad = true;
                            this.sort('registries', 'total_vulns')
                        }
                     }
                },
                methods: {
        		    registry_images(index){
        		        this.pageLoad = false;
        		        this.images = this.registries[index].images;
        		        this.activeRegistry = index;
        		        this.sort('registries', 'vulns_found')
                        if(this.images.length == 0){
                            this.showLineChart = false;
                            this.activeImage = null
                        }else{
                            this.activeImage = this.registries[index].images[0];
                            this.scan_history(0);
                        }

                    },
                    sort(collection, column, event){
                      if(column == 'name' || column == 'is_running' || column == 'registry'){
                          this[collection].sort((a, b) => a[column].localeCompare(b[column]))
                      }else{
                          this[collection].sort((a, b) => b[column] - a[column]);
                      }
                    },
                    scan_history(index){
                        this.activeIndex = index;
                        this.activeImage = this.images[index];
                        chart_data = [['Date', 'Critical', 'High', 'Medium']]
                        image = this.images[index]
                        for(scan_history of image['scan_history']){
                            chart_data.push([this.parse_date(scan_history.date), scan_history.crit_vulns, scan_history.high_vulns, scan_history.med_vulns])
                        }

                         if(this.images.length == 0){
                            this.showLineChart = false;
                        }else{
                            this.showLineChart = true;
                            drawImageChart(image, chart_data)
                        }

                    },
                    parse_date(rawDate){
                        const date = new Date(rawDate);
                        return moment(date).format('MM-DD');
                    },
                    type: function(index){
        		        reg_type = this.registries[index].type
                        if(reg_type == 'HUB' || reg_type == 'ENGINE' || reg_type == 'API'){
                            reg_type = 'docker'
                        }else if(reg_type == 'ACR'){
                            reg_type = 'microsoft'
                        }else if(reg_type == 'GCR'){
                            reg_type = 'google'
                        }

                        return &&REGTYPE&&
                    }
                },
                computed:{
                    scanTitle: function(){
                        if(this.activeImage) {
                            return &&SCANHISTORY&&
                        }else{
                            return ''
                        }
                    },
        		    current_registry: function(){
                          if(this.pageLoad){
                              return "Overall"
                          }else {
                              return this.registries[this.activeRegistry].name
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
                    url: function(prefix){

                      if(!prefix.search("https")){
                          return prefix.substring(8);
                      }else{
                          return prefix
                      }
                    }
                }
        	});
        </script>
        </body>
        </html>
	`
	scanHistory := "`Scan History: ${this.activeImage.name} (${this.activeImage.scan_history.length} scan/s)`"
	scanReplace := strings.Replace(template, "&&SCANHISTORY&&", scanHistory, -1)
	regType := "`<i class=\"fab fa-${reg_type.toLowerCase()}\"></i>`;"
	typeReplace := strings.Replace(scanReplace, "&&REGTYPE&&", regType, -1)
	regReplace := strings.Replace(typeReplace, "registries: []", "registries: "+regData, -1)
	response := strings.Replace(regReplace, "images: []", "images: "+topData, -1)
	return response
}
