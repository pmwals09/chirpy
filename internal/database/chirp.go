package database

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
}
