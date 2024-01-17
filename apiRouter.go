package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
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
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userResponse struct {
	Email       string `json:"email"`
	Id          int    `json:"id"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

func getApiRouter(db *database.DB, apiCfg apiConfig) http.Handler {
	apiRouter := chi.NewRouter()
	apiRouter.Get("/healthz", healthzHandler)
	apiRouter.Post("/chirps", func(w http.ResponseWriter, r *http.Request) {
		chirpPostHandler(w, r, db, apiCfg.jwtSecret)
	})
	apiRouter.Get("/chirps", func(w http.ResponseWriter, r *http.Request) {
		chirpGetHandler(w, r, db)
	})
	apiRouter.Get("/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		chirpGetByIdHandler(w, r, db)
	})
	apiRouter.Delete("/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		chirpDeleteByIdHandler(w, r, db, apiCfg.jwtSecret)
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
	apiRouter.Post("/refresh", func(w http.ResponseWriter, r *http.Request) {
		refreshPostHandler(w, r, db, apiCfg.jwtSecret)
	})
	apiRouter.Post("/revoke", func(w http.ResponseWriter, r *http.Request) {
		revokePostHandler(w, r, db, apiCfg.jwtSecret)
	})
	apiRouter.Post("/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		polkaWebhookPostHandler(w, r, db)
	})

	return apiRouter
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func chirpPostHandler(w http.ResponseWriter, r *http.Request, db *database.DB, jwtSecret string) {
	token, err := getTokenFromRequest(r, jwtSecret)
	if err != nil || !token.Valid {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	userId, err := token.Claims.GetSubject()
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	decoder := json.NewDecoder(r.Body)
	newChirp := database.Chirp{}
	err = decoder.Decode(&newChirp)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "Something went wrong")
		return
	}

	if len(newChirp.Body) > 140 {
		respondWithErr(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	cleanedBody := cleanChirp(newChirp.Body)
	id, err := strconv.Atoi(userId)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	c, err := db.CreateChirp(cleanedBody, id)
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

func chirpDeleteByIdHandler(w http.ResponseWriter, r *http.Request, db *database.DB, jwtSecret string) {
	token, err := getTokenFromRequest(r, jwtSecret)
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	chirpID, err := strconv.Atoi(chi.URLParam(r, "chirpID"))
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
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
	err = db.DeleteChirp(chirpID, id)
	if err != nil {
		if errors.Is(err, database.ErrUnauthorized{}) {
			respondWithErr(w, http.StatusForbidden, "Unauthorized")
			return
		}
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	w.WriteHeader(http.StatusOK)
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
	data, err := json.Marshal(userResponse{Email: u.Email, Id: u.Id, IsChirpyRed: u.IsChirpyRed})
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
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	tokenString := strings.Split(authHeader, " ")[1]
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if issuer != "chirpy-access" {
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
	data, err := json.Marshal(userResponse{Email: user.Email, Id: user.Id, IsChirpyRed: user.IsChirpyRed})
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

	userId := strconv.Itoa(user.Id)
	accessTokenString, err := getNewAccessTokenString(userId, jwtSecret)

	refreshTokenClaims := jwt.RegisteredClaims{
		Issuer:    "chirpy-refresh",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 60)),
		Subject:   strconv.Itoa(user.Id),
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(jwtSecret))

	type response struct {
		Email        string `json:"email"`
		Id           int    `json:"id"`
		IsChirpyRed  bool   `json:"is_chirpy_red"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	data, err := json.Marshal(response{
		Email:        user.Email,
		Id:           user.Id,
		IsChirpyRed:  user.IsChirpyRed,
		Token:        accessTokenString,
		RefreshToken: refreshTokenString,
	})
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
	return
}

func refreshPostHandler(w http.ResponseWriter, r *http.Request, db *database.DB, jwtSecret string) {
	token, err := getTokenFromRequest(r, jwtSecret)
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	isValid := token.Valid
	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	isRefresh := issuer == "chirpy-refresh"
	isRevoked, err := db.IsRefreshTokenRevoked(token.Raw)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Unauthorized")
		return
	}
	if !isValid || !isRefresh || isRevoked {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	} else {
		userId, err := token.Claims.GetSubject()
		if err != nil {
			respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		newToken, err := getNewAccessTokenString(userId, jwtSecret)
		if err != nil {
			respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
		data, err := json.Marshal(map[string]string{"token": newToken})
		if err != nil {
			respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(data))
		return
	}
}

func revokePostHandler(w http.ResponseWriter, r *http.Request, db *database.DB, jwtSecret string) {
	token, err := getTokenFromRequest(r, jwtSecret)
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	err = db.RevokeRefreshToken(token.Raw)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "Something went wrong")
	}
	w.WriteHeader(http.StatusOK)
	return
}

func polkaWebhookPostHandler(w http.ResponseWriter, r *http.Request, db *database.DB) {
	type webhookdata struct {
		UserId int `json:"user_id"`
	}
	type webhookstruct struct {
		Event string      `json:"event"`
		Data  webhookdata `json:"data"`
	}
	decoder := json.NewDecoder(r.Body)
	webhookReq := webhookstruct{}
	err := decoder.Decode(&webhookReq)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "Invalid request")
		return
	}
	if webhookReq.Event != "user.upgraded" {
		w.WriteHeader(http.StatusOK)
		return
	}
  api := r.Header.Get("Authorization")
  apiFields := strings.Fields(api)
  if len(apiFields) == 2 && apiFields[0] == "ApiKey" && apiFields[1] == os.Getenv("POLKA_KEY") {
    err = db.UpgradeUserToRed(webhookReq.Data.UserId)
    if err != nil {
      if errors.Is(err, database.ErrUserDoesNotExist{}) {
        w.WriteHeader(http.StatusNotFound)
        return
      } else {
        w.WriteHeader(http.StatusInternalServerError)
        return
      }
    }
    w.WriteHeader(http.StatusOK)
    return
  }
  w.WriteHeader(http.StatusUnauthorized)
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

func getNewAccessTokenString(userId string, jwtSecret string) (string, error) {
	accessTokenClaims := jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject:   userId,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	return accessToken.SignedString([]byte(jwtSecret))
}

func getTokenFromRequest(r *http.Request, jwtSecret string) (*jwt.Token, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return &jwt.Token{}, errors.New("No auth header")
	}

	tokenString := strings.Split(authHeader, " ")[1]
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return token, err
	}
	return token, nil
}
