package app

import (
	"auth_service/internal/config"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	repeatInterval = time.Minute
)

func Run() {
	if err := config.LoadFromEnv(".env"); err != nil {
		log.Fatalf("config.LoadFromFile(): %v", err)
	}
}

func connectToDatabase(url string) (*pgxpool.Pool, error) {
	var retries int
	var maxRetries = 5

	var pool *pgxpool.Pool
	var err error
	if len(url) == 0 {
		return nil, errors.New("missing DB_URL environment variable")
	}

	for {
		if retries >= maxRetries {
			return nil, fmt.Errorf("couldn't connect to the database after %d retries", retries)
		}

		pool, err = pgxpool.New(context.Background(), url)
		if err != nil {
			log.Fatalf("couldn't connect to the database: %v", err)
			time.Sleep(2 * time.Second)

			retries++
			continue
		}

		log.Println("successfully connected")
		return pool, nil
	}
}
