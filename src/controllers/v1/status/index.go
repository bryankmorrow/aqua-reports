package status

import "net/http"

// Index - return the v1 api status
func Index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("V1 status is live!"))
}
