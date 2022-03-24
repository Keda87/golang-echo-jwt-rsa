package main

import (
	"crypto/rsa"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	refreshAudience = "refresh"
	accessAudience  = "access"
)

type JWTCustomClaim struct {
	UserID   int64  `json:"userId,omitempty"`
	UserName string `json:"userName,omitempty"`
	jwt.StandardClaims
}

func initRSAKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {

	currentDIR, err := os.Getwd()
	if err != nil {
		return nil, nil, err
	}

	var (
		privateKey     *rsa.PrivateKey
		publicKey      *rsa.PublicKey
		privateKeyPath = filepath.Join(currentDIR, "example.key")
		publicKeyPath  = filepath.Join(currentDIR, "example.pem")
	)

	rawPrivateKey, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil, err
	}

	rawPublicKey, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(rawPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(rawPublicKey)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func generateAccessToken(privateKey *rsa.PrivateKey, userId int64, userName string) string {
	accessTokenClaim := &JWTCustomClaim{
		UserID:   userId,
		UserName: userName,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 15).Unix(), // expires within 15 minutes.
			Audience:  accessAudience,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, accessTokenClaim)

	jwtToken, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	return jwtToken
}

func generateRefreshToken(privateKey *rsa.PrivateKey, userId int64, userName string) string {
	refreshTokenClaim := &JWTCustomClaim{
		UserID:   userId,
		UserName: userName,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(), // expires within a week.
			Audience:  refreshAudience,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshTokenClaim)

	jwtToken, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	return jwtToken
}
