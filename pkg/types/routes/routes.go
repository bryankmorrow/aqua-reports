package routes

import (
	"net/http"
)

// Routes is a slice of Route
type Routes []Route

// Route contains the Handler data
type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

// SubRoutePackage routes the middleware
type SubRoutePackage struct {
	Routes     Routes
	Middleware func(next http.Handler) http.Handler
}
