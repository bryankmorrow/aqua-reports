package status

import "net/http"

// Index - return the v1 api status
func Index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Aqua Reports V2 status is live!"))
}
