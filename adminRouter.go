package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func getAdminRouter(apiConfig *apiConfig) http.Handler {
	adminRouter := chi.NewRouter()
	adminRouter.Get("/metrics", apiConfig.metricsHandler)
	adminRouter.HandleFunc("/reset", apiConfig.resetHandler)
	return adminRouter
}
