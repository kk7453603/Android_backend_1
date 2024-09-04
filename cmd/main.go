package main

import (
	"auth_service/internal/repository"
	"auth_service/internal/router"
	"auth_service/internal/service"
	"os"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	log "github.com/labstack/gommon/log"
)

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
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

	repo := repository.New(e.Logger)
	repo.Migrate()
	serv := service.New(repo)
	r := router.New(serv, e.Logger)

	apiGroup := e.Group("")
	r.InitRoutes(apiGroup)

	if err := e.Start(os.Getenv("Service_Url")); err != nil {
		e.Logger.Fatalf("service start error: %v", err)
	}

	e.Logger.Info(os.Getenv("Service_Url"))
}
