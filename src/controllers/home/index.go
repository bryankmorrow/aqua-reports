package home

import "net/http"

// Index - Home route
func Index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to Aqua Reports"))
}
