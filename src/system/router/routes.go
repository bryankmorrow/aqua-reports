package router

import (
	"log"
	"net/http"

	"github.com/BryanKMorrow/reports-v2/pkg/types/routes"
	HomeHandler "github.com/BryanKMorrow/reports-v2/src/controllers/home"
)

// Middleware - Main Middleware function
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Inside main middleware.")
		next.ServeHTTP(w, r)
	})
}

// GetRoutes - Handle Authentication
func GetRoutes() routes.Routes {

	return routes.Routes{
		routes.Route{"Home", "GET", "/", HomeHandler.Index},
	}
}
