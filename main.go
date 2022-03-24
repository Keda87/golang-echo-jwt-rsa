package main

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	privateKey, publicKey, err := initRSAKey()
	if err != nil {
		panic(err)
	}

	e := echo.New()

	jwtConfig := middleware.JWTConfig{
		Claims:     &JWTCustomClaim{},
		SigningKey: privateKey,
		KeyFunc: func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		},
	}

	var (
		useCase = NewUseCase(privateKey, publicKey)
		handler = NewHandler(useCase)
	)

	e.POST("/api/auth-token", handler.handleAuthToken)
	e.POST("api/refresh-token", handler.handleRefreshToken)
	e.GET("/api/private", handler.handlePrivateAPI, middleware.JWTWithConfig(jwtConfig))

	e.Logger.Fatal(e.Start(":5000"))
}
