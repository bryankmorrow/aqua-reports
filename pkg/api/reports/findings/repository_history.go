package findings

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/BryanKMorrow/aqua-sdk-go/client"
	"github.com/BryanKMorrow/aqua-sdk-go/types/images"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
	"github.com/gorilla/mux"
)

type RepositoryHistory []images.History

// TagHandler receives the http request, collects the tag history for all images and returns status to requester
func TagHandler(w http.ResponseWriter, r *http.Request) {
	var rh RepositoryHistory
	params := mux.Vars(r)
	queue := make(chan reports.Response)
	response := rh.Get(params, queue)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (rh *RepositoryHistory) Get(params map[string]string, queue chan reports.Response) reports.Response {
	defer reports.Track(reports.RunningTime("tagHistory.Get"))
	reports.UnescapeURLQuery(params)
	cli := reports.GetClient(rh)
	var rhl []images.History
	// Get all repositories
	repos, _, _, _ := cli.GetRepositories(0, 1000, nil)
	// Loop through all repositories and get the tags
	for _, repo := range repos.Result {
		history := images.History{
			Name:     repo.Name,
			Registry: repo.Registry,
		}
		params["registry"] = repo.Registry
		params["repository"] = repo.Name
		var rt []images.Tag
		img, remaining, _, total := cli.GetAllImages(0, 1000, params, nil)
		q := make(chan images.Tag)
		log.Printf("Remaining: %d  Total: %d", remaining, total)
		if total > 0 {
			for _, image := range img.Result {
				go GetTags(cli, image, q)
			}
			for _, image := range img.Result {
				go GetTags(cli, image, q)
			}
			for tag := range q {
				rt = append(rt, tag)
				log.Printf("Processing: %s/%s:%s", repo.Registry, repo.Name, tag.Tag)
				break
			}
			history.Tags = rt
			rhl = append(rhl, history)
		}
		log.Println("Done with repository: ", repo.Name)
	}
	var response = reports.Response{
		Message: "Tag History for all repos: " + strconv.Itoa(repos.Count),
		URL:     "",
		Status:  "Write Successful",
	}
	data, _ := json.Marshal(rhl)
	log.Println(string(data))
	return response
}

func GetTags(cli *client.Client, image images.Image, q chan images.Tag) {
	var t images.Tag
	i, err := cli.GetImage(image.Registry, image.Repository, image.Tag)
	if err != nil {
		log.Println("Error getting tags: ", err)
	} else {
		t = images.Tag{
			Tag:        i.Tag,
			Created:    i.Metadata.Created,
			VulnsFound: i.VulnsFound,
			CritVulns:  i.CritVulns,
			HighVulns:  i.HighVulns,
			MedVulns:   i.MedVulns,
			LowVulns:   i.LowVulns,
			NegVulns:   i.NegVulns,
		}
	}
	q <- t
}
