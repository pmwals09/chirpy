package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

func getApiRouter() http.Handler {
	apiRouter := chi.NewRouter()
	apiRouter.Get("/healthz", healthzHandler)
	apiRouter.Post("/validate_chirp", validateChirpHandler)

	return apiRouter
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	type chirp struct {
		Body string `json:"body"`
	}
	type errorResponse struct {
		Error string `json:"error"`
	}
	type successResponse struct {
		CleanedBody string `json:"cleaned_body"`
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

	cleanedBody := cleanChirp(newChirp.Body)
	data, _ := json.Marshal(successResponse{cleanedBody})
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
	return
}

func cleanChirp(chirp string) string {
	dirtyWords := []string{"kerfuffle", "sharbert", "fornax"}
	out := make([]string, 0)
	for _, tok := range strings.Fields(chirp) {
		isDirtyWord := false
		for _, w := range dirtyWords {
			if strings.ToLower(tok) == strings.ToLower(w) {
				isDirtyWord = true
				break
			}
		}
		if isDirtyWord {
			out = append(out, "****")
		} else {
			out = append(out, tok)
		}
	}
	return strings.Join(out, " ")
}
