package models

import (
	"github.com/golang-jwt/jwt/v5"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	ID       int
	Username string
	Password string
}

type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}
