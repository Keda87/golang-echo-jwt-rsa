package main

type Token struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type CustomError struct {
	Err string `json:"error"`
}

func (m *CustomError) Error() string {
	return m.Err
}
