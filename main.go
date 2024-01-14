package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type apiConfig struct {
	fileserverHits int
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits += 1
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`
<html>

<body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
</body>

</html>`, cfg.fileserverHits)))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	r := chi.NewRouter()
	apiConfig := apiConfig{}
	fsHandler := apiConfig.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)

	apiRouter := chi.NewRouter()
	apiRouter.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	apiRouter.Post("/validate_chirp", func(w http.ResponseWriter, r *http.Request) {
		type chirp struct {
			Body string `json:"body"`
		}
		type errorResponse struct {
			Error string `json:"error"`
		}
		type successResponse struct {
			Valid bool `json:"valid"`
		}
		decoder := json.NewDecoder(r.Body)
		newChirp := chirp{}
		err := decoder.Decode(&newChirp)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			decodeError := errorResponse{"Something went wrong"}
			data, _ := json.Marshal(decodeError)
			w.Write([]byte(data))
			return
		}

		if len(newChirp.Body) > 140 {
			lengthError := errorResponse{"Chirp is too long"}
			data, err := json.Marshal(lengthError)
			if err != nil {
				marshalError := errorResponse{"Something went wrong"}
				data, _ := json.Marshal(marshalError)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(data))
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(data))
			return
		}

		data, _ := json.Marshal(successResponse{true})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(data))
		return
	})

	r.Mount("/api", apiRouter)

	adminRouter := chi.NewRouter()
	adminRouter.Get("/metrics", apiConfig.metricsHandler)
	adminRouter.HandleFunc("/reset", apiConfig.resetHandler)

	r.Mount("/admin", adminRouter)

	corsRouter := corsMiddleware(r)
	server := http.Server{
		Addr:    ":8080",
		Handler: corsRouter,
	}
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
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
