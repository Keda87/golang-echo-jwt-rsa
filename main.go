package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

type JWTCustomClaim struct {
	UserID   int64  `json:"userId,omitempty"`
	UserName string `json:"userName,omitempty"`
	jwt.StandardClaims
}

func initRSAKey() {
	currentDIR, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	var (
		privateKeyPath = filepath.Join(currentDIR, "example.key")
		publicKeyPath  = filepath.Join(currentDIR, "example.pem")
	)

	rawPrivateKey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		panic(err)
	}

	rawPublicKey, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		panic(err)
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(rawPrivateKey)
	if err != nil {
		panic(err)
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(rawPublicKey)
	if err != nil {
		panic(err)
	}

	privateKey = privKey
	publicKey = pubKey
}

func generateJWT(data *JWTCustomClaim) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, data)

	jwtToken, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	return jwtToken
}

func handleAuthToken(c echo.Context) error {
	var (
		username          = c.FormValue("username")
		password          = c.FormValue("password")
		isCredentialValid = username == "admin" && password == "admin" // dummy logic, replace with your own.
	)

	if !isCredentialValid {
		resp := map[string]string{
			"error": "invalid credential",
		}
		return c.JSON(http.StatusUnauthorized, resp)
	}

	accessTokenClaim := &JWTCustomClaim{
		UserID:   1,
		UserName: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 15).Unix(), // expires within 15 minutes.
		},
	}

	refreshTokenClaim := &JWTCustomClaim{
		UserID: 1,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(), // expires within a week.
		},
	}

	successResp := map[string]string{
		"accessToken":  generateJWT(accessTokenClaim),
		"refreshToken": generateJWT(refreshTokenClaim),
	}

	return c.JSON(http.StatusOK, successResp)
}

func handleRefreshToken(c echo.Context) error {
	refreshToken := c.FormValue("refreshToken")

	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return publicKey, nil
	})
	if err != nil {
		resp := map[string]string{
			"error": "invalid token",
		}
		return c.JSON(http.StatusUnauthorized, resp)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden access"})
	}

	if !token.Valid {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden access"})
	}

	userID := claims["userId"].(float64)
	if int64(userID) != 1 { // dummy logic, replace with your own.
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden access"})
	}

	accessTokenClaim := &JWTCustomClaim{
		UserID:   1,
		UserName: "admin",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 15).Unix(), // expires within 15 minutes.
		},
	}

	refreshTokenClaim := &JWTCustomClaim{
		UserID: 1,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(), // expires within a week.
		},
	}

	successResp := map[string]string{
		"accessToken":  generateJWT(accessTokenClaim),
		"refreshToken": generateJWT(refreshTokenClaim),
	}

	return c.JSON(http.StatusOK, successResp)
}

func handlePrivateAPI(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"message": "Welcome!"})
}

func main() {
	initRSAKey()

	e := echo.New()

	jwtConfig := middleware.JWTConfig{
		Claims:     &JWTCustomClaim{},
		SigningKey: privateKey,
		KeyFunc: func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		},
	}

	e.POST("/api/auth-token", handleAuthToken)
	e.POST("api/refresh-token", handleRefreshToken)
	e.GET("/api/private", handlePrivateAPI, middleware.JWTWithConfig(jwtConfig))

	e.Logger.Fatal(e.Start(":5000"))
}
