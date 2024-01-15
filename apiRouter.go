package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/pmwals09/chirpy/internal/database"
	"golang.org/x/crypto/bcrypt"
)

type errorResponse struct {
	Error string `json:"error"`
}

type userRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userResponse struct {
	Email string `json:"email"`
	Id    int    `json:"id"`
}

func getApiRouter(db *database.DB) http.Handler {
	apiRouter := chi.NewRouter()
	apiRouter.Get("/healthz", healthzHandler)
	apiRouter.Post("/chirps", func(w http.ResponseWriter, r *http.Request) {
		chirpPostHandler(w, r, db)
	})
	apiRouter.Get("/chirps", func(w http.ResponseWriter, r *http.Request) {
		chirpGetHandler(w, r, db)
	})
	apiRouter.Get("/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		chirpGetByIdHandler(w, r, db)
	})
	apiRouter.Post("/users", func(w http.ResponseWriter, r *http.Request) {
		userPostHandler(w, r, db)
	})
	apiRouter.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		loginPostHandler(w, r, db)
	})

	return apiRouter
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func chirpPostHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	decoder := json.NewDecoder(r.Body)
	newChirp := database.Chirp{}
	err := decoder.Decode(&newChirp)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "Something went wrong")
		return
	}

	if len(newChirp.Body) > 140 {
		respondWithErr(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	cleanedBody := cleanChirp(newChirp.Body)
	c, err := db.CreateChirp(cleanedBody)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	data, err := json.Marshal(c)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(data))
	return
}

func chirpGetHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	chirps, err := db.GetChirps()
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	data, err := json.Marshal(chirps)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
	return
}

func chirpGetByIdHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	chirpID := chi.URLParam(r, "chirpID")
	chirp, err := db.GetChirpById(chirpID)
	if err != nil {
		if errors.Is(err, database.ErrChirpNotFound{}) {
			w.WriteHeader(http.StatusNotFound)
			return
		} else {
			respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
	}
	data, err := json.Marshal(chirp)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
	return
}

func userPostHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	req := userRequest{}
	err := decoder.Decode(&req)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "Something went wrong")
		return
	}
	pwHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	u, err := db.CreateUser(req.Email, string(pwHash))
	if err != nil {
		if errors.Is(err, database.ErrUserExists{}) {
			respondWithErr(w, http.StatusInternalServerError, "A user with that email already exists")
			return
		} else {
			respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
	}
	data, err := json.Marshal(userResponse{Email: u.Email, Id: u.Id})
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(data))
	return
}

func loginPostHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	req := userRequest{}
	err := decoder.Decode(&req)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "Something went wrong")
		return
	}
	user, err := db.GetUserByEmail(req.Email)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	data, err := json.Marshal(userResponse{Email: user.Email, Id: user.Id})
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
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

func respondWithErr(w http.ResponseWriter, code int, msg string) {
	err := errorResponse{msg}
	data, _ := json.Marshal(err)
	w.WriteHeader(code)
	w.Write([]byte(data))
}
