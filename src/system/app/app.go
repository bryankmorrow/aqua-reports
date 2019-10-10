package app

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/BryanKMorrow/reports-v2/src/system/router"
	"github.com/gorilla/handlers"
)

// Server - structure for the API server
type Server struct {
	port string
}

// NewServer - Instantiate a Server struct
func NewServer() Server {
	return Server{}
}

// Init all vals
func (s *Server) Init(port string) {
	log.Println("Initializing server...")
	s.port = ":" + port
}

// Start the server
func (s *Server) Start() {
	log.Println("Starting server on port" + s.port)

	r := router.NewRouter()

	r.Init()

	handler := handlers.LoggingHandler(os.Stdout, handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "PUT", "PATCH", "POST", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Origin", "Cache-Control", "X-App-Token"}),
		handlers.ExposedHeaders([]string{""}),
		handlers.MaxAge(1000),
		handlers.AllowCredentials(),
	)(r.Router))
	handler = handlers.RecoveryHandler(handlers.PrintRecoveryStack(true))(handler)

	newServer := &http.Server{
		Handler:      handler,
		Addr:         "0.0.0.0" + s.port,
		WriteTimeout: 60 * time.Second,
		ReadTimeout:  30 * time.Second,
	}

	log.Fatal(newServer.ListenAndServe())
}
