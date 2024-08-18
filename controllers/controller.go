package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"simple_jwt_based_auth/models"
	"simple_jwt_based_auth/repo"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("your_secret_key")

func LogIn(w http.ResponseWriter, r *http.Request) {

	var creds models.Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	user, exists := repo.GetUser(creds.Username)
	if !exists || user.Password != creds.Password {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	accessToken, err := generateJWT(user.ID, 15*time.Minute)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateJWT(user.ID, 30*24*time.Hour)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", "Bearer "+accessToken)
	w.Header().Set("Refresh-Token", refreshToken)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged in successfully"))
}

func generateJWT(userID int, expiration time.Duration) (string, error) {
	claims := models.Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func Refresh(w http.ResponseWriter, r *http.Request) {

	refreshToken := r.Header.Get("Refresh-Token")
	if refreshToken == "" {
		http.Error(w, "No refresh token provided", http.StatusUnauthorized)
		return
	}

	claims, err := parseJWT(refreshToken)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	newAccessToken, err := generateJWT(claims.UserID, 15*time.Minute)
	if err != nil {
		http.Error(w, "Failed to generate new access token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", "Bearer "+newAccessToken)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Access token refreshed successfully"))
}

func parseJWT(tokenString string) (*models.Claims, error) {

	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*models.Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func GetItems(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	tokenString := authHeader[len("Bearer "):]
	claims, err := parseJWT(tokenString)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// доступ к полезной нагрузке(payload)
	fmt.Printf("Current user ID: %d\n", claims.UserID)

	items := repo.GetAllItems()
	response, err := json.Marshal(items)
	if err != nil {
		http.Error(w, "Failed to marshal items", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}
