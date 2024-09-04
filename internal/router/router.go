package router

import (
	customErrors "auth_service/internal/errors"
	"auth_service/internal/jwt"
	"auth_service/internal/models"
	"errors"
	"net/http"
	"os"
	"time"

	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Service interface {
	InsertUser(models.UserToken) error
	RefreshUser(models.UserToken) (models.UserToken, error)
	RegisterUser(models.UserRegistration, models.UserToken) error
	ChangePassword(login, oldPassword, newPassword string) error
	RecoverPassword(email string) error
	ConfirmEmail(newEmail string) error
	ConfirmCode(code string) (bool, error)
	RequestDeletion(login string) error
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
	g.POST("/api/user/changePassword", r.ChangePassword, echojwt.JWT(os.Getenv("SECRET")))
	g.POST("/api/user/recover/:email", r.RecoverPassword, echojwt.JWT(os.Getenv("SECRET")))
	g.POST("/api/user/code", r.ConfirmEmail, echojwt.JWT(os.Getenv("SECRET")))
	g.POST("/api/user/checkcode", r.ConfirmCode, echojwt.JWT(os.Getenv("SECRET")))
	g.POST("/api/user/requestForDeletion", r.RequestDeletion, echojwt.JWT(os.Getenv("SECRET")))
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

func (r *Router) CreateTokens(c echo.Context) error {
	ipAddress := r.getIPAddress(c)
	r.logger.Infof("CreateTokens request from IP: %s", ipAddress)

	var user models.User
	err := c.Bind(&user)
	if err != nil {
		r.logger.Debugf("user bind error: %v", err)
		return c.JSON(http.StatusBadRequest, models.Response_Error{Error: "user data not valid"})
	}
	accessToken, refreshToken, err := jwt.CreateTokens(user.Login, user.Password)
	if err != nil {
		r.logger.Errorf("Error creating JWT tokens: %v", err)
		c.JSON(customErrors.ErrInternalServerErrorJWTCreateError.HttpStatus, customErrors.ErrInternalServerErrorJWTCreateError)
	}
	data := models.UserToken{Login: user.Login, Password: user.Password, AccessToken: accessToken, RefreshToken: refreshToken}
	if err := r.serv.InsertUser(data); err != nil {
		if errors.Is(err, customErrors.ErrUserExists) {
			return c.JSON(http.StatusBadRequest, customErrors.ErrUserAlreadyExists.WithMessage("User already exists"))
		}
		r.logger.Debug("Create tokens error: " + err.Error())
		return c.JSON(http.StatusInternalServerError, customErrors.ErrInternalServerError.Default())
	}

	response := models.Response{Status: 200, Payload: struct {
		AccessToken  string
		RefreshToken string
	}{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}}

	return c.JSON(http.StatusOK, response)
}

func (r *Router) Refresh(c echo.Context) error {
	ipAddress := r.getIPAddress(c)
	r.logger.Infof("Refresh request from IP: %s", ipAddress)

	refreshToken := c.FormValue("refresh_token")
	accessToken := c.FormValue("access_token")
	var user models.User
	err := c.Bind(&user)
	if err != nil {
		r.logger.Debugf("user bind error: %v", err)
		return c.JSON(customErrors.ErrBadRequestParseBody.HttpStatus, customErrors.ErrBadRequestParseBody.WithMessage("user data not valid"))
	}

	userdata := models.UserToken{Login: user.Login, Password: user.Password, AccessToken: accessToken, RefreshToken: refreshToken}
	data, error_custom := r.serv.RefreshUser(userdata)
	if error_custom != nil {
		if errors.Is(err, customErrors.ErrTokenExpired) {
			return c.JSON(customErrors.ErrInvalidOrExpiredToken.HttpStatus, customErrors.ErrInvalidOrExpiredToken.WithMessage("Refresh token is expired"))
		}
		if errors.Is(err, customErrors.ErrTokensMatch) {
			return c.JSON(customErrors.ErrInvalidOrExpiredToken.HttpStatus, customErrors.ErrInvalidOrExpiredToken.WithMessage("Tokens doesn't match"))
		}
		if errors.Is(err, customErrors.ErrRefreshToken) {
			return c.JSON(customErrors.ErrInvalidOrExpiredToken.HttpStatus, customErrors.ErrInvalidOrExpiredToken.WithMessage("Invalid refresh token"))
		}
		if errors.Is(err, customErrors.ErrAccessToken) {
			return c.JSON(customErrors.ErrInvalidOrExpiredToken.HttpStatus, customErrors.ErrInvalidOrExpiredToken.WithMessage("Invalid access token"))
		}
		r.logger.Errorf("Refresh token error: %v", err)
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

func (r *Router) RegisterUser(c echo.Context) error {
	ipAddress := r.getIPAddress(c)
	r.logger.Infof("RegisterUser request from IP: %s", ipAddress)

	var user models.UserRegistration
	if err := c.Bind(&user); err != nil {
		r.logger.Errorf("Bind error: %v", err)
		return c.JSON(customErrors.ErrBadRequestParseBody.HttpStatus, customErrors.ErrBadRequestParseBody.WithMessage("Invalid input data"))
	}
	accessToken, refreshToken, err := jwt.CreateTokens(user.Email, user.Password)
	if err != nil {
		r.logger.Errorf("Error creating JWT tokens: %v", err)
		return c.JSON(customErrors.ErrInternalServerError.HttpStatus, customErrors.ErrInternalServerError.WithMessage("Error creating JWT tokens"))
	}
	data := models.UserToken{Login: user.Email, Password: user.Password, AccessToken: accessToken, RefreshToken: refreshToken}

	if err := r.serv.RegisterUser(user, data); err != nil {
		if errors.Is(err, customErrors.ErrUserExists) {
			return c.JSON(customErrors.ErrUserAlreadyExists.HttpStatus, customErrors.ErrUserAlreadyExists.WithMessage("This email address is already in use"))
		}
		r.logger.Error("Registration error: " + err.Error())
		return c.JSON(customErrors.ErrInternalServerError.HttpStatus, customErrors.ErrInternalServerError.Default())
	}
	return c.JSON(http.StatusOK, models.Response{Status: 200, Payload: "User registered successfully"})
}

func (r *Router) ChangePassword(c echo.Context) error {
	ipAddress := r.getIPAddress(c)
	r.logger.Infof("ChangePassword request from IP: %s", ipAddress)

	var req models.ChangePasswordRequest
	if err := c.Bind(&req); err != nil {
		r.logger.Errorf("Bind error: %v", err)
		return c.JSON(customErrors.ErrBadRequestParseBody.HttpStatus, customErrors.ErrBadRequestParseBody.WithMessage("Invalid input data"))
	}
	login := c.Get("user").(*models.User).Login
	if err := r.serv.ChangePassword(login, req.OldPassword, req.NewPassword); err != nil {
		if errors.Is(err, customErrors.ErrPasswordFormat) {
			return c.JSON(customErrors.ErrUserPasswordFormat.HttpStatus, customErrors.ErrUserPasswordFormat.Default())
		}
		r.logger.Debugf("Change password error")
		return c.JSON(customErrors.ErrInternalServerError.HttpStatus, customErrors.ErrInternalServerError.Default())
	}
	return c.JSON(http.StatusOK, models.Response{Status: 200, Payload: "Password changed successfully"})
}

func (r *Router) RecoverPassword(c echo.Context) error {
	ipAddress := r.getIPAddress(c)
	r.logger.Infof("RecoverPassword request from IP: %s", ipAddress)

	email := c.Param("email")
	if err := r.serv.RecoverPassword(email); err != nil {
		if errors.Is(err, customErrors.ErrEmailNotFound) {
			return c.JSON(customErrors.ErrUserEmailNotFound.HttpStatus, customErrors.ErrUserEmailNotFound.Default())
		}
		r.logger.Error("Recover password error: " + err.Error())
		return c.JSON(customErrors.ErrInternalServerError.HttpStatus, customErrors.ErrInternalServerError.Default())
	}
	return c.JSON(http.StatusOK, models.Response{Status: 200, Payload: "Recovery email sent"})
}

func (r *Router) ConfirmEmail(c echo.Context) error {
	ipAddress := r.getIPAddress(c)
	r.logger.Infof("ConfirmEmail request from IP: %s", ipAddress)

	var req models.ConfirmEmailRequest
	if err := c.Bind(&req); err != nil {
		r.logger.Errorf("Bind error: %v", err)
		return c.JSON(customErrors.ErrBadRequestParseBody.HttpStatus, customErrors.ErrBadRequestParseBody.WithMessage("Invalid input data"))
	}
	if err := r.serv.ConfirmEmail(req.NewEmail); err != nil {

		if errors.Is(err, customErrors.ErrEmailExists) {
			return c.JSON(customErrors.ErrUserEmailExists.HttpStatus, customErrors.ErrUserEmailExists.WithMessage("This email address is already in use"))
		}
		if errors.Is(err, customErrors.ErrEmailInvalid) {
			return c.JSON(customErrors.ErrUserEmailInvalid.HttpStatus, customErrors.ErrUserEmailInvalid.WithMessage("Invalid email address"))
		}
		r.logger.Debug("Confirm email error: " + err.Error())
		r.logger.Error("Confirm email error")
		return c.JSON(customErrors.ErrInternalServerError.HttpStatus, customErrors.ErrInternalServerError.Default())
	}
	return c.JSON(http.StatusOK, models.Response{Status: 200, Payload: "Email confirmed"})
}

func (r *Router) ConfirmCode(c echo.Context) error {
	ipAddress := r.getIPAddress(c)
	r.logger.Infof("ConfirmCode request from IP: %s", ipAddress)

	var req models.ConfirmCodeRequest
	if err := c.Bind(&req); err != nil {
		r.logger.Errorf("Bind error: %v", err)
		return c.JSON(customErrors.ErrBadRequestParseBody.HttpStatus, customErrors.ErrBadRequestParseBody.WithMessage("Invalid input data"))
	}
	isValid, err := r.serv.ConfirmCode(req.Code)
	if err != nil {
		r.logger.Debug("Confirm code error: " + err.Error())
		r.logger.Error("Confirm code error")
		return c.JSON(customErrors.ErrInternalServerError.HttpStatus, customErrors.ErrInternalServerError.Default())
	}
	return c.JSON(http.StatusOK, models.Response{Status: 200, Payload: isValid})
}

func (r *Router) RequestDeletion(c echo.Context) error {
	ipAddress := r.getIPAddress(c)
	r.logger.Infof("RequestDeletion request from IP: %s", ipAddress)

	login := c.Get("user").(*models.User).Login
	if err := r.serv.RequestDeletion(login); err != nil {
		r.logger.Debug("Request deletion error: " + err.Error())
		return c.JSON(customErrors.ErrInternalServerError.HttpStatus, customErrors.ErrInternalServerError.Default())
	}
	return c.JSON(http.StatusOK, models.Response{Status: 200, Payload: "User deletion requested"})
}
