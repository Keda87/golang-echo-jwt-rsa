package main

import (
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt"
)

type AuthUseCaseInterface interface {
	GetToken(username, password string) (Token, error)
	RefreshToken(token string) (Token, error)
}

type AuthUseCase struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewUseCase(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) AuthUseCase {
	return AuthUseCase{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

func (uc AuthUseCase) GetToken(username, password string) (Token, error) {

	// dummy logic, replace with your own.
	isCredentialValid := username == "admin" && password == "admin"

	if !isCredentialValid {
		return Token{}, &CustomError{Err: "invalid credentials"}
	}

	token := Token{
		AccessToken:  generateAccessToken(uc.privateKey, 1, username),
		RefreshToken: generateRefreshToken(uc.privateKey, 1, username),
	}

	return token, nil
}

func (uc AuthUseCase) RefreshToken(refreshToken string) (Token, error) {

	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return uc.publicKey, nil
	})
	if err != nil {
		return Token{}, &CustomError{Err: "invalid token"}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return Token{}, &CustomError{Err: "forbidden access"}
	}

	if !token.Valid {
		return Token{}, &CustomError{Err: "forbidden access"}
	}

	if claims["aud"].(string) != refreshAudience {
		return Token{}, &CustomError{Err: "invalid refresh token"}
	}

	userID := claims["userId"].(float64)

	// dummy logic, replace with your own.
	if int64(userID) != 1 {
		return Token{}, &CustomError{Err: "forbidden access"}
	}

	responseToken := Token{
		AccessToken:  generateAccessToken(uc.privateKey, 1, "admin"),
		RefreshToken: generateRefreshToken(uc.privateKey, 1, "admin"),
	}

	return responseToken, nil
}
