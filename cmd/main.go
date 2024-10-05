package main

import (
	"auth_service/internal/repository"
	"auth_service/internal/router"
	"auth_service/internal/service"
	"os"

	_ "auth_service/docs"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	log "github.com/labstack/gommon/log"
	echoSwagger "github.com/swaggo/echo-swagger"
)

// @title           Auth Service API
// @version         1.0
// @description     This is an authentication service API.

// @contact.name   API Support
// @contact.url    http://www.example.com/support
// @contact.email  support@example.com
// @securityDefinitions.apikey  JWT
// @in                          header
// @name                        Authorization
// @host      localhost:8000
// @BasePath  /
func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.GET("/swagger/*", echoSwagger.WrapHandler)
	err := godotenv.Load()
	if err != nil {
		e.Logger.Fatalf("godotenv error: %v", err)
	}
	e.Logger.Info("Переменные среды загружены")

	if os.Getenv("DEBUG") == "on" {
		e.Debug = true
		e.Logger.SetLevel(log.DEBUG)
		e.Logger.Info("DEBUG режим включен")
	}

	repo, err := repository.New(e.Logger)
	if err != nil {
		e.Logger.Fatalf("Failed to initialize repository: %v", err)
	}
	repo.Migrate()
	serv := service.New(repo, e.Logger)
	r := router.New(serv, e.Logger)

	apiGroup := e.Group("")
	r.InitRoutes(apiGroup)

	if err := e.Start(os.Getenv("Service_Url")); err != nil {
		e.Logger.Fatalf("service start error: %v", err)
	}

	e.Logger.Info(os.Getenv("Service_Url"))
}
