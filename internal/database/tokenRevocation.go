package database

import "time"

type TokenRevocation struct {
	Token       string    `json:"token"`
	TimeRevoked time.Time `json:"time_revoked"`
}
