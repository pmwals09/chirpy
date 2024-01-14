package main

import (
	"fmt"
	"net/http"
)

func main() {
  mux := http.NewServeMux()
  corsMux := corsMiddleware(mux)
  server := http.Server{
    Addr: ":8080",
    Handler: corsMux,
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
