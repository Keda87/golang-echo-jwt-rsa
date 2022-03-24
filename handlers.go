package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type AuthHandlers struct {
	authUseCase AuthUseCaseInterface
}

func NewHandler(authUseCase AuthUseCaseInterface) AuthHandlers {
	return AuthHandlers{authUseCase: authUseCase}
}

func (h AuthHandlers) handleAuthToken(c echo.Context) error {
	var (
		username = c.FormValue("username")
		password = c.FormValue("password")
	)

	result, err := h.authUseCase.GetToken(username, password)
	if err != nil {
		return echo.ErrUnauthorized
	}

	return c.JSON(http.StatusOK, result)
}

func (h AuthHandlers) handleRefreshToken(c echo.Context) error {
	refreshToken := c.FormValue("refreshToken")

	result, err := h.authUseCase.RefreshToken(refreshToken)
	if err != nil {
		return echo.ErrForbidden
	}

	return c.JSON(http.StatusOK, result)
}

func (h AuthHandlers) handlePrivateAPI(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"message": "Welcome!"})
}
