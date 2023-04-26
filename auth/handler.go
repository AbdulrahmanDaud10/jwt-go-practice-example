package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var jwtkey = []byte("my_secret_key")

// A dummy implementation of users and their passwords
var users = map[string]string{
	"userOne": "password123",
	"userTwo": "password456",
}

// Create model the structure of a user, that will be an implentation pf both the request body and in the DB
type qualifications struct {
	Password string `json:""password"`
	userName string `json: "username"`
}

type Claims struct {
	userName string `json: "username"`
	jwt.RegisteredClaims
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	var credentials qualifications
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the expected password from our memory app
	expectedPassword, ok := users[credentials.userName]

	// If the pasword exists for a given user
	// If its the same pasword as received, we can proceed
	// If not, then we return an authorized status responce
	if !ok || expectedPassword != credentials.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Declaring the expiration time of the token
	expirationTime := time.Now().Add(5 * time.Minute)
	// Create the JWT claims, which includes the username and the expiry time
	claims := &Claims{
		userName: credentials.userName,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Declare the token with the algorithm used for the signing and the claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtkey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}
