package repository

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestDatabaseConnection(t *testing.T) {
	e := echo.New().Logger
	sql_handler := New(e)
	pool, err := pgxpool.New(context.Background(), sql_handler.Dsn)
	if err != nil {
		t.Fatalf("Unable to create connection pool: %v", err)
	}
	defer pool.Close()
	assert.NotNil(t, sql_handler.DB)
	assert.NoError(t, err)
}
