package router

import (
	customErrors "auth_service/internal/errors"
	"auth_service/internal/jwt"
	"auth_service/internal/models"
	"errors"
	"net/http"
	"os"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	InsertUser(userData models.UserToken) error
	RefreshUser(refreshToken string) (models.UserToken, error)
	RegisterUser(user models.UserRegistration) error
	ChangePassword(login, oldPassword, newPassword string) error
	GetUserByLogin(login string) (*models.User, error)
}

type Router struct {
	serv   Service
	logger echo.Logger
}

func New(serv Service, lg echo.Logger) *Router {
	return &Router{serv: serv, logger: lg}
}

func (r *Router) InitRoutes(g *echo.Group) {
	rateLimiterConfig := middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      10,
			Burst:     5,
			ExpiresIn: 1 * time.Minute,
		}),
		IdentifierExtractor: func(c echo.Context) (string, error) {
			return r.getIPAddress(c), nil
		},
	}
	g.Use(middleware.RateLimiterWithConfig(rateLimiterConfig))

	g.POST("/api/createToken", r.CreateTokens)
	g.POST("/api/updateToken", r.Refresh)
	g.POST("/api/user/register", r.RegisterUser)
	g.POST("/api/user/changePassword", r.ChangePassword, echojwt.WithConfig(
		echojwt.Config{
			SigningKey:  []byte(os.Getenv("SECRET")),
			TokenLookup: "header:Authorization",
		},
	))
	//g.POST("/api/user/requestForDeletion", r.RequestDeletion, echojwt.JWT(os.Getenv("SECRET")))
}

func (r *Router) getIPAddress(c echo.Context) string {
	IPAddress := c.RealIP()
	if IPAddress == "" {
		IPAddress = c.Request().Header.Get("X-Real-IP")
	}
	if IPAddress == "" {
		IPAddress = c.Request().Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = c.Request().RemoteAddr
	}
	return IPAddress
}

// CreateTokens godoc
// @Summary      Create new access and refresh tokens
// @Description  Generates new access and refresh tokens for a user
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        user  body      models.RegUser  true  "User Credentials"
// @Success      200   {object}  models.Response
// @Failure      400   {object}  models.Response_Error
// @Failure      500   {object}  models.Response_Error
// @Router       /api/createToken [post]
func (r *Router) CreateTokens(c echo.Context) error {
	var usr models.RegUser
	if err := c.Bind(&usr); err != nil {
		r.logger.Debugf("user bind error: %v", err)
		return c.JSON(http.StatusBadRequest, models.ResponseError{Error: "Invalid user data"})
	}
	user := usr.ForDomain()

	// Проверяем пользователя
	storedUser, err := r.serv.GetUserByLogin(user.Login)
	if err != nil {
		r.logger.Errorf("User not found: %v", err)
		return c.JSON(http.StatusUnauthorized, models.ResponseError{Error: "Invalid credentials"})
	}

	// Проверяем пароль
	if err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password)); err != nil {
		r.logger.Errorf("Incorrect password for user: %s", user.Login)
		return c.JSON(http.StatusUnauthorized, models.ResponseError{Error: "Invalid credentials"})
	}

	refreshToken, err := jwt.CreateRefreshToken(user.Login)
	if err != nil {
		r.logger.Errorf("Error creating refresh token: %v", err)
		return c.JSON(http.StatusInternalServerError, models.ResponseError{Error: "Error creating refresh token"})
	}

	// Обновляем токены в БД
	newtokens, err := r.serv.RefreshUser(refreshToken)
	if err != nil {
		r.logger.Errorf("Error updating tokens: %v", err)
		return c.JSON(http.StatusInternalServerError, models.ResponseError{Error: "Error updating tokens"})
	}

	response := models.Response{Status: 200, Payload: newtokens}

	return c.JSON(http.StatusOK, response)
}

// Refresh godoc
// @Summary      Refresh access and refresh tokens
// @Description  Refreshes tokens using provided refresh token
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        refresh_token  formData  string  true  "Refresh Token"
// @Success      200            {object}  models.Response
// @Failure      400            {object}  models.Response_Error
// @Failure      500            {object}  models.Response_Error
// @Router       /api/updateToken [post]
func (r *Router) Refresh(c echo.Context) error {
	ipAddress := r.getIPAddress(c)
	r.logger.Infof("Refresh request from IP: %s", ipAddress)

	refreshToken := c.FormValue("refresh_token")
	//accessToken := c.FormValue("access_token")
	//var user models.User
	//err := c.Bind(&user)
	//if err != nil {
	//	r.logger.Debugf("user bind error: %v", err)
	//	return c.JSON(customErrors.ErrBadRequestParseBody.HttpStatus, customErrors.ErrBadRequestParseBody.WithMessage("user data not valid"))
	//}

	//userdata := models.UserToken{Login: user.Login, Password: user.Password, AccessToken: accessToken, RefreshToken: refreshToken}
	data, error_custom := r.serv.RefreshUser(refreshToken)
	if error_custom != nil {
		if errors.Is(error_custom, customErrors.ErrTokenExpired) {
			return c.JSON(customErrors.ErrInvalidOrExpiredToken.HttpStatus, customErrors.ErrInvalidOrExpiredToken.WithMessage("Refresh token is expired"))
		}
		if errors.Is(error_custom, customErrors.ErrTokensMatch) {
			return c.JSON(customErrors.ErrInvalidOrExpiredToken.HttpStatus, customErrors.ErrInvalidOrExpiredToken.WithMessage("Tokens doesn't match"))
		}
		if errors.Is(error_custom, customErrors.ErrRefreshToken) {
			return c.JSON(customErrors.ErrInvalidOrExpiredToken.HttpStatus, customErrors.ErrInvalidOrExpiredToken.WithMessage("Invalid refresh token"))
		}
		if errors.Is(error_custom, customErrors.ErrAccessToken) {
			return c.JSON(customErrors.ErrInvalidOrExpiredToken.HttpStatus, customErrors.ErrInvalidOrExpiredToken.WithMessage("Invalid access token"))
		}
		r.logger.Errorf("Refresh token error: %v", error_custom)
		return c.JSON(customErrors.ErrInternalServerError.HttpStatus, customErrors.ErrInternalServerError)
	}
	response := models.Response{Status: 200, Payload: struct {
		AccessToken  string
		RefreshToken string
	}{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
	}}

	return c.JSON(http.StatusOK, response)
}

// RegisterUser godoc
// @Summary      Register a new user
// @Description  Registers a new user with email, password, and nickname
// @Tags         User Management
// @Accept       json
// @Produce      json
// @Param        user  body      models.UserRegistration  true  "User Registration Data"
// @Success      200   {object}  models.Response
// @Failure      400   {object}  models.Response_Error
// @Failure      500   {object}  models.Response_Error
// @Router       /api/user/register [post]
func (r *Router) RegisterUser(c echo.Context) error {
	ipAddress := r.getIPAddress(c)
	r.logger.Infof("RegisterUser request from IP: %s", ipAddress)

	var user models.UserRegistration
	if err := c.Bind(&user); err != nil {
		r.logger.Errorf("Bind error: %v", err)
		return c.JSON(customErrors.ErrBadRequestParseBody.HttpStatus, customErrors.ErrBadRequestParseBody.WithMessage("Invalid input data"))
	}

	/*
		accessToken, err := jwt.CreateAccessToken(user.Nickname)
		if err != nil {
			r.logger.Errorf("Error creating JWT tokens: %v", err)
			return c.JSON(customErrors.ErrInternalServerError.HttpStatus, customErrors.ErrInternalServerError.WithMessage("Error creating JWT tokens"))
		}

		refreshToken, err := jwt.CreateRefreshToken(user.Nickname)
		if err != nil {
			r.logger.Errorf("Error creating JWT tokens: %v", err)
			return c.JSON(customErrors.ErrInternalServerError.HttpStatus, customErrors.ErrInternalServerError.WithMessage("Error creating JWT tokens"))
		}

		data := models.UserToken{Login: user.Nickname, Password: user.Password, AccessToken: accessToken, RefreshToken: refreshToken}
	*/
	if err := r.serv.RegisterUser(user); err != nil {
		if errors.Is(err, customErrors.ErrUserExists) {
			return c.JSON(customErrors.ErrUserAlreadyExists.HttpStatus, customErrors.ErrUserAlreadyExists.WithMessage("This user already exists"))
		}
		r.logger.Error("Registration error: " + err.Error())
		return c.JSON(customErrors.ErrInternalServerError.HttpStatus, customErrors.ErrInternalServerError.Default())
	}
	return c.JSON(http.StatusOK, models.Response{Status: 200, Payload: "User registered successfully"})
}

// ChangePassword godoc
// @Summary      Change user password
// @Description  Allows an authenticated user to change their password
// @Tags         User Management
// @Accept       json
// @Produce      json
// @Param        request  body      models.ChangePasswordRequest  true  "Password Change Request"
// @Success      200      {object}  models.Response
// @Failure      400      {object}  models.Response_Error
// @Failure      500      {object}  models.Response_Error
// @Security     JWT
// @Router       /api/user/changePassword [post]
func (r *Router) ChangePassword(c echo.Context) error {
	ipAddress := r.getIPAddress(c)
	r.logger.Infof("ChangePassword request from IP: %s", ipAddress)

	var req models.ChangePasswordRequest
	if err := c.Bind(&req); err != nil {
		r.logger.Errorf("Bind error: %v", err)
		return c.JSON(customErrors.ErrBadRequestParseBody.HttpStatus, customErrors.ErrBadRequestParseBody.WithMessage("Invalid input data"))
	}

	// Получаем токен из контекста
	userToken := c.Get("user").(*jwt5.Token)

	// Получаем клеймы из токена
	claims := userToken.Claims.(jwt5.MapClaims)
	login := claims["login"].(string)

	r.logger.Infof("ChangePassword login: %s", login)
	if err := r.serv.ChangePassword(login, req.OldPassword, req.NewPassword); err != nil {
		return c.JSON(http.StatusBadRequest, "wrong old password")
	}
	return c.JSON(http.StatusOK, models.Response{Status: 200, Payload: "Password changed successfully"})
}
