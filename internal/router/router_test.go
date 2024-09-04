package router

import (
	customErrors "auth_service/internal/errors"
	"auth_service/internal/models"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

type mockService struct{}

func (m *mockService) InsertUser(models.UserToken) error {
	return nil
}

func (m *mockService) RefreshUser(user models.UserToken) (models.UserToken, error) {
	return user, nil
}

func (m *mockService) RegisterUser(user models.UserRegistration, tokens models.UserToken) error {
	if user.Email == "exists@example.com" {
		return customErrors.ErrUserExists
	}
	return nil
}

func (m *mockService) ChangePassword(login, oldPassword, newPassword string) error {
	return nil
}

func (m *mockService) RecoverPassword(email string) error {
	return nil
}

func (m *mockService) ConfirmEmail(newEmail string) error {
	return nil
}

func (m *mockService) ConfirmCode(code string) (bool, error) {
	return true, nil
}

func (m *mockService) RequestDeletion(login string) error {
	return nil
}

func TestCreateTokens(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/createToken", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	router := New(&mockService{}, e.Logger)
	err := router.CreateTokens(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRegisterUser(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/user/register", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	router := New(&mockService{}, e.Logger)
	err := router.RegisterUser(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRegisterUserExists(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/user/register", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Set the email to an existing one
	c.SetParamNames("email")
	c.SetParamValues("exists@example.com")

	router := New(&mockService{}, e.Logger)
	err := router.RegisterUser(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestChangePassword(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/user/changePassword", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Set a JWT token in the header
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": "test@example.com",
		"exp":  time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(os.Getenv("SECRET")))
	req.Header.Set("Authorization", "Bearer "+tokenString)

	router := New(&mockService{}, e.Logger)
	err := router.ChangePassword(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRecoverPassword(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/user/recover/test@example.com", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	router := New(&mockService{}, e.Logger)
	err := router.RecoverPassword(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestConfirmEmail(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/user/code", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	router := New(&mockService{}, e.Logger)
	err := router.ConfirmEmail(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestConfirmCode(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/user/checkcode", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	router := New(&mockService{}, e.Logger)
	err := router.ConfirmCode(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequestDeletion(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/user/requestForDeletion", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Set a JWT token in the header
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": "test@example.com",
		"exp":  time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(os.Getenv("SECRET")))
	req.Header.Set("Authorization", "Bearer "+tokenString)

	router := New(&mockService{}, e.Logger)
	err := router.RequestDeletion(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}
