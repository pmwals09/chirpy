package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"github.com/pmwals09/chirpy/internal/database"
)

func main() {
	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()
	if *dbg {
		err := os.Remove("./database.json")
		if err != nil {
			fmt.Println(err)
			os.Exit(3)
			return
		}
	}

	err := godotenv.Load()
	if err != nil {
		fmt.Println(err)
		os.Exit(4)
		return
	}

	r := chi.NewRouter()
	apiConfig := apiConfig{jwtSecret: os.Getenv("JWT_SECRET")}
	db, err := database.NewDB("./database.json")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
		return
	}
	fsHandler := apiConfig.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)

	r.Mount("/api", getApiRouter(db, apiConfig))

	r.Mount("/admin", getAdminRouter(&apiConfig))

	corsRouter := corsMiddleware(r)
	server := http.Server{
		Addr:    ":8080",
		Handler: corsRouter,
	}
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
		return
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
