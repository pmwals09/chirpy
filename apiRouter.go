package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pmwals09/chirpy/internal/database"
	"golang.org/x/crypto/bcrypt"
)

type errorResponse struct {
	Error string `json:"error"`
}

type userRequest struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

type userResponse struct {
	Email string `json:"email"`
	Id    int    `json:"id"`
}

func getApiRouter(db *database.DB, apiCfg apiConfig) http.Handler {
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
	apiRouter.Put("/users", func(w http.ResponseWriter, r *http.Request) {
		userPutHandler(w, r, db, apiCfg.jwtSecret)
	})
	apiRouter.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		loginPostHandler(w, r, db, apiCfg.jwtSecret)
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

func userPutHandler(w http.ResponseWriter, r *http.Request, db *database.DB, jwtSecret string) {
	// needs auth
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// validate the token
	tokenString := strings.Split(authHeader, " ")[1]
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	newUser := userRequest{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&newUser)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "Something went wrong")
		return
	}
	userId, err := token.Claims.GetSubject()
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	id, err := strconv.Atoi(userId)
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
	}
	pwHash, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	user, err := db.UpdateUser(id, newUser.Email, string(pwHash))
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	data, err := json.Marshal(userResponse{Email: user.Email, Id: user.Id})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
}

func loginPostHandler(w http.ResponseWriter, r *http.Request, db *database.DB, jwtSecret string) {
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

	defaultExpiration := time.Hour * 24
	var expiration time.Duration
	if req.ExpiresInSeconds > 0 {
		expiration = time.Second * time.Duration(req.ExpiresInSeconds)
	} else {
		expiration = defaultExpiration
	}
	tokenClaims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
		Subject:   strconv.Itoa(user.Id),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	type response struct {
		Email string `json:"email"`
		Id    int    `json:"id"`
		Token string `json:"token"`
	}
	data, err := json.Marshal(response{Email: user.Email, Id: user.Id, Token: tokenString})
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
