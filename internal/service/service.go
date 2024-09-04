package service

import (
	customErrors "auth_service/internal/errors"
	"auth_service/internal/jwt"
	"auth_service/internal/models"
	"time"

	"github.com/labstack/echo/v4"
)

//go:generate mockgen -source=service.go -destination=mocks/mock.go
type Repository interface {
	InsertUser(models.UserToken) error
	UpdateUser(models.UserToken) error
	GetToken(string, string) (string, error)
	CheckUser(string, string) (bool, error)
	RegisterUser(models.UserRegistration, models.UserToken) error
	ChangePassword(login, oldPassword, newPassword string) error
	RecoverPassword(email string) error
	ConfirmEmail(newEmail string) error
	ConfirmCode(code string) (bool, error)
	RequestDeletion(login string) error
}

type Service struct {
	repo   Repository
	logger echo.Logger
}

func New(rep Repository) *Service {
	return &Service{repo: rep}
}

func (s *Service) InsertUser(userData models.UserToken) error {
	isExists, err := s.repo.CheckUser(userData.Login, userData.Password)
	if err != nil {
		s.logger.Errorf("Cannot get data: %v", err)
		return err
	}
	if isExists {
		hashedToken, err := jwt.HashRefresh(userData.RefreshToken)
		if err != nil {
			s.logger.Errorf("Cannot hash refresh token: %v", err)
			return err
		}
		userData.RefreshToken = hashedToken
		if err = s.repo.UpdateUser(userData); err != nil {
			s.logger.Errorf("Cannot insert user: %v", err)
			return err
		}
		return nil
	}
	hashedToken, err := jwt.HashRefresh(userData.RefreshToken)
	if err != nil {
		s.logger.Errorf("Cannot hash refresh token: %v", err)
		return err
	}
	userData.RefreshToken = hashedToken

	if err := s.repo.InsertUser(userData); err != nil {
		s.logger.Errorf("Cannot insert user: %v", err)
		return err
	}

	return nil
}

func (s *Service) RefreshUser(userData models.UserToken) (models.UserToken, error) {
	accessToken := userData.AccessToken
	refreshToken := userData.RefreshToken
	accessClaims, err := jwt.ParseAccess(accessToken)
	if err != nil {
		s.logger.Errorf("Error to parse access token: %v", err)
		return models.UserToken{}, err
	}
	access_name := accessClaims.Login
	access_pass := accessClaims.Password
	accessTime := accessClaims.Time
	accessSalt := accessClaims.Salt

	refreshClaims, err := jwt.ParseRefresh(refreshToken)
	if err != nil {
		s.logger.Fatalf("Cannot parse token", err)
		return models.UserToken{}, err
	}

	refresh_name := refreshClaims.Login
	refresh_pass := refreshClaims.Password
	refreshTime := refreshClaims.Time
	refreshSalt := refreshClaims.Salt

	if refreshClaims.ExpTime < time.Now().Unix() {
		s.logger.Error("Refresh token is expired")
		return models.UserToken{}, customErrors.ErrTokenExpired
	}
	if access_name == refresh_name && access_pass == refresh_pass && accessSalt == refreshSalt && refreshTime == accessTime {
		hashedToken, err := jwt.HashRefresh(refreshToken)
		if err != nil {
			s.logger.Errorf("Cannot hash refresh token", err)
			return models.UserToken{}, err
		}

		oldToken, err := s.repo.GetToken(userData.Login, userData.Password)

		if err != nil {
			s.logger.Errorf("Cannot get old token", err)
		}

		if oldToken != hashedToken {
			s.logger.Errorf("Refresh tokens doesn't match")
			return models.UserToken{}, customErrors.ErrTokensMatch
		}
		newAccessToken, newRefreshToken, err := jwt.CreateTokens(userData.Login, userData.Password)
		if err != nil {
			s.logger.Errorf("Cannot create tokens", err)
			return models.UserToken{}, err
		}

		hashedToken, err = jwt.HashRefresh(newRefreshToken)
		if err != nil {
			s.logger.Errorf("Cannot hash refresh token", err)
			return models.UserToken{}, err
		}

		newData := models.UserToken{Login: userData.Login, Password: userData.Password, AccessToken: newAccessToken, RefreshToken: hashedToken}

		if err = s.repo.UpdateUser(newData); err != nil {
			s.logger.Errorf("Cannot insert data")
			return models.UserToken{}, err
		}
		newData.RefreshToken = newRefreshToken
		return newData, nil
	} else {
		s.logger.Error("Tokens doesn't match")
		return models.UserToken{}, customErrors.ErrTokensMatch
	}

}

func (s *Service) RegisterUser(user models.UserRegistration, tokens models.UserToken) error {
	if err := s.repo.RegisterUser(user, tokens); err != nil {
		s.logger.Errorf("Cannot register user: %v", err)
		return err
	}
	return nil
}

func (s *Service) ChangePassword(login, oldPassword, newPassword string) error {
	return s.repo.ChangePassword(login, oldPassword, newPassword)
}

func (s *Service) RecoverPassword(email string) error {
	return s.repo.RecoverPassword(email)
}

func (s *Service) ConfirmEmail(newEmail string) error {
	return s.repo.ConfirmEmail(newEmail)
}

func (s *Service) ConfirmCode(code string) (bool, error) {
	return s.repo.ConfirmCode(code)
}

func (s *Service) RequestDeletion(login string) error {
	return s.repo.RequestDeletion(login)
}
