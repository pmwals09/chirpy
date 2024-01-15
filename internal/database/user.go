package database

type User struct {
	Email        string `json:"email"`
	Id           int    `json:"id"`
	PasswordHash string `json:"password_hash"`
}
