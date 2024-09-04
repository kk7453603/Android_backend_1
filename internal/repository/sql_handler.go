package repository

import (
	customErrors "auth_service/internal/errors"
	"auth_service/internal/jwt"
	"auth_service/internal/models"
	"auth_service/pkg/migrate"
	"context"
	"errors"
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

func New(e echo.Logger) *SqlHandler {
	dsn := "postgres://" + os.Getenv("DB_USER") + ":" + os.Getenv("DB_PASSWORD") + "@" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + "/" + os.Getenv("DB_NAME")
	e.Debugf("DSN: %s", dsn)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		e.Errorf("SqlHandler init error: %v", err)
	}
	return &SqlHandler{DB: pool, Dsn: dsn, elog: e}
}

func (h *SqlHandler) Migrate() {
	if err := migrate.ApplyMigrations(h.Dsn); err != nil {
		h.elog.Errorf("Migration Error: %s", err)
		return
	}
	h.elog.Info("Migration complete")
}

// сейчас тестирую это
func (h *SqlHandler) RefreshUser(user models.UserToken) (models.UserToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	query := `SELECT user_id FROM refresh_tokens WHERE refresh_token = $1`
	var userID int
	err := h.DB.QueryRow(ctx, query, user.RefreshToken).Scan(&userID)
	if err != nil {
		h.elog.Debugf("No user with current refresh token: %s", err)
		return models.UserToken{}, customErrors.ErrRefreshToken
	}
	refreshToken, err := jwt.ParseRefresh(user.RefreshToken)

	if err != nil {
		h.elog.Errorf("Refresh token parse error: %s", err)
		return models.UserToken{}, err
	}
	// еще не истекло время жизни и данные не были изменены
	if refreshToken.ExpTime < time.Now().Unix() && refreshToken.Login == user.Login && refreshToken.Password == user.Password {
		return user, nil
	}
	// Генерация новых токенов (Access и Refresh)

	newAccessToken, newRefreshToken, err := jwt.CreateTokens(user.Login, user.Password)

	if err != nil {
		h.elog.Errorf("Token regenerate error: %s", err)
		return models.UserToken{}, err
	}

	updateTokenQuery := `UPDATE refresh_tokens SET refresh_token = $1 WHERE user_id = $2`
	_, err = h.DB.Exec(ctx, updateTokenQuery, newRefreshToken, userID)
	if err != nil {
		h.elog.Errorf("DB refresh token update error: %s", err)
		return models.UserToken{}, err
	}

	return models.UserToken{
		Login:        user.Login,
		Password:     user.Password,
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

// исправлено
func (h *SqlHandler) RegisterUser(user models.UserRegistration, tokens models.UserToken) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	query := `INSERT INTO users (email, password, first_name, middle_name, last_name, phone_number, trade_point_name, notifications_enabled, project_id) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`
	var userID int
	err := h.DB.QueryRow(ctx, query, user.Email, user.Password, user.FirstName, user.MiddleName, user.LastName, user.PhoneNumber, user.TradePointName, user.NotificationsEnabled, user.ProjectId).Scan(&userID)
	if err != nil {
		return err
	}

	if userID == 0 {
		return customErrors.ErrUserAddError
	}

	for _, field := range user.RegFields {
		fieldQuery := `INSERT INTO reg_fields (user_id, field_to_answer, field_value) VALUES ($1, $2, $3)`
		_, err = h.DB.Exec(ctx, fieldQuery, userID, field.FieldToAnswer, field.FieldValue)
		if err != nil {
			return err
		}
	}
	tokenQuery := `INSERT INTO refresh_tokens (user_id, refresh_token) VALUES ($1, $2)`
	_, err = h.DB.Exec(ctx, tokenQuery, userID, tokens.RefreshToken)
	return err
}

func (h *SqlHandler) ChangePassword(login, oldPassword, newPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `UPDATE users SET password = $1 WHERE email = $2 AND password = $3`
	cmdTag, err := h.DB.Exec(ctx, query, newPassword, login, oldPassword)
	if err != nil {
		return err
	}

	if cmdTag.RowsAffected() == 0 {
		return errors.New("incorrect old password")
	}
	return nil
}

func (h *SqlHandler) RecoverPassword(email string) error {
	// Здесь вы можете реализовать отправку email с токеном для восстановления пароля
	// В данном примере просто вернем nil, что имитирует успешную отправку
	return nil
}

func (h *SqlHandler) ConfirmEmail(newEmail string) error {
	return nil
}

func (h *SqlHandler) ConfirmCode(code string) (bool, error) {
	// Здесь вы можете реализовать проверку кода подтверждения
	// В данном примере просто вернем true, что имитирует успешную проверку
	return true, nil
}

func (h *SqlHandler) RequestDeletion(login string) error {
	return nil
}

func (h *SqlHandler) CheckUser(string, string) (bool, error) {
	return true, nil
}

func (h *SqlHandler) GetToken(string, string) (string, error) {
	return "", nil
}

func (h *SqlHandler) InsertUser(models.UserToken) error {
	return nil
}

func (h *SqlHandler) UpdateUser(models.UserToken) error {
	return nil
}
