package repository

import (
	"auth_service/internal/models"
	"auth_service/pkg/migrate"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

type SqlHandler struct {
	DB   *pgxpool.Pool
	Dsn  string
	elog echo.Logger
}

func New(e echo.Logger) (*SqlHandler, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)
	e.Debugf("DSN: %s", dsn)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		e.Errorf("SqlHandler init error: %v", err)
		return nil, err
	}
	return &SqlHandler{DB: pool, Dsn: dsn, elog: e}, nil
}

func (h *SqlHandler) Migrate() {
	if err := migrate.ApplyMigrations(h.Dsn); err != nil {
		h.elog.Errorf("Migration Error: %s", err)
		return
	}
	h.elog.Info("Migration complete")
}

func (h *SqlHandler) InsertUser(user models.UserToken) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `INSERT INTO users (username, passwd, access_token, refresh_token) VALUES ($1, $2, $3, $4)`
	_, err := h.DB.Exec(ctx, query, user.Login, user.Password, user.AccessToken, user.RefreshToken)
	if err != nil {
		h.elog.Errorf("Error inserting user: %v", err)
		return err
	}
	return nil
}

func (h *SqlHandler) GetUserByLogin(login string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `SELECT username, passwd, access_token, refresh_token FROM users WHERE username = $1`
	row := h.DB.QueryRow(ctx, query, login)

	var user models.User
	err := row.Scan(&user.Login, &user.Password, &user.AccessToken, &user.RefreshToken)
	if err != nil {
		h.elog.Errorf("Error getting user: %v", err)
		return nil, err
	}
	return &user, nil
}

func (h *SqlHandler) UpdateTokens(login, accessToken, refreshToken string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `UPDATE users SET access_token = $1, refresh_token = $2 WHERE username = $3`
	cmdTag, err := h.DB.Exec(ctx, query, accessToken, refreshToken, login)
	if err != nil {
		h.elog.Errorf("Error updating tokens: %v", err)
		return err
	}
	if cmdTag.RowsAffected() == 0 {
		return errors.New("no rows updated")
	}
	return nil
}

func (h *SqlHandler) Changepasswd(login, newpasswd string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `UPDATE users SET passwd = $1 WHERE username = $2`
	cmdTag, err := h.DB.Exec(ctx, query, newpasswd, login)
	if err != nil {
		h.elog.Errorf("Error changing passwd: %v", err)
		return err
	}
	if cmdTag.RowsAffected() == 0 {
		return errors.New("no rows updated")
	}
	return nil
}
