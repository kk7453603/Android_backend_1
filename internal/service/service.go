package service

import (
	"auth_service/internal/jwt"
	"auth_service/internal/models"
	"errors"
	"os"

	customErrors "auth_service/internal/errors"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

//go:generate mockgen -source=service.go -destination=mocks/mock.go
type Repository interface {
	InsertUser(user models.UserToken) error
	GetUserByLogin(login string) (*models.User, error)
	UpdateTokens(login, accessToken, refreshToken string) error
	Changepasswd(login, newpasswd string) error
}

type Service struct {
	repo   Repository
	logger echo.Logger
}

func New(rep Repository, logger echo.Logger) *Service {
	return &Service{repo: rep, logger: logger}
}

func (s *Service) InsertUser(userData models.UserToken) error {
	// Проверяем, существует ли пользователь
	user, err := s.repo.GetUserByLogin(userData.Login)
	if user != nil {
		s.logger.Errorf("User already exists: %s", userData.Login)
		return errors.New("user already exists")
	}

	if err != nil {
		s.logger.Errorf("GetUserByLogin error: %s", err)
		return err
	}

	// Хэшируем пароль перед сохранением
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Errorf("Error hashing password: %v", err)
		return err
	}
	userData.Password = string(hashedPassword)

	// Сохраняем пользователя
	if err := s.repo.InsertUser(userData); err != nil {
		s.logger.Errorf("Error inserting user: %v", err)
		return err
	}
	return nil
}

func (s *Service) RefreshUser(refreshToken string) (models.UserToken, error) {
	// Валидация refresh токена
	token, err := jwt.ValidateToken(refreshToken, os.Getenv("SECRET"))
	if err != nil {
		s.logger.Errorf("Invalid refresh token: %v", err)
		return models.UserToken{}, customErrors.ErrRefreshToken
	}
	claims, err := jwt.GetClaims(token)
	if err != nil {
		s.logger.Errorf("Error getting claims from token: %v", err)
		return models.UserToken{}, customErrors.ErrTokensMatch
	}
	login := claims["login"].(string)

	// Получаем пользователя из БД
	_, err = s.repo.GetUserByLogin(login)
	if err != nil {
		s.logger.Errorf("User not found: %v", err)
		return models.UserToken{}, err
	}

	// Генерируем новые токены
	newAccessToken, err := jwt.CreateAccessToken(login)
	if err != nil {
		s.logger.Errorf("Error creating access token: %v", err)
		return models.UserToken{}, customErrors.ErrAccessToken
	}
	newRefreshToken, err := jwt.CreateRefreshToken(login)
	if err != nil {
		s.logger.Errorf("Error creating refresh token: %v", err)
		return models.UserToken{}, customErrors.ErrRefreshToken
	}

	// Обновляем токены в БД
	if err := s.repo.UpdateTokens(login, newAccessToken, newRefreshToken); err != nil {
		s.logger.Errorf("Error updating tokens: %v", err)
		return models.UserToken{}, err
	}

	return models.UserToken{
		Login:        login,
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *Service) RegisterUser(user models.UserRegistration) error {
	// Проверяем, существует ли пользователь
	existingUser, err := s.repo.GetUserByLogin(user.Nickname)
	if err == nil && existingUser != nil {
		s.logger.Errorf("User already exists: %s", user.Nickname)
		return errors.New("user already exists")
	}

	// Хэшируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Errorf("Error hashing password: %v", err)
		return err
	}

	// Генерируем токены
	accessToken, err := jwt.CreateAccessToken(user.Nickname)
	if err != nil {
		s.logger.Errorf("Error creating access token: %v", err)
		return err
	}
	refreshToken, err := jwt.CreateRefreshToken(user.Nickname)
	if err != nil {
		s.logger.Errorf("Error creating refresh token: %v", err)
		return err
	}

	// Сохраняем пользователя
	userData := models.UserToken{
		Login:        user.Nickname,
		Password:     string(hashedPassword),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	if err := s.repo.InsertUser(userData); err != nil {
		s.logger.Errorf("Error inserting user: %v", err)
		return customErrors.ErrUserExists
	}
	return nil
}

func (s *Service) ChangePassword(login, oldPassword, newPassword string) error {
	// Получаем пользователя
	user, err := s.repo.GetUserByLogin(login)
	if err != nil {
		s.logger.Errorf("User not found: %v", err)
		return err
	}

	// Проверяем старый пароль
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		s.logger.Errorf("Incorrect old password for user: %s", login)
		return errors.New("incorrect old password")
	}

	// Хэшируем новый пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Errorf("Error hashing new password: %v", err)
		return err
	}

	// Обновляем пароль в БД
	if err := s.repo.Changepasswd(login, string(hashedPassword)); err != nil {
		s.logger.Errorf("Error changing password: %v", err)
		return err
	}
	return nil
}

func (s *Service) GetUserByLogin(login string) (*models.User, error) {
	return s.repo.GetUserByLogin(login)
}
