package config

import (
	"github.com/joho/godotenv"
)

// сюда можно вынести подгрузку переменных среды по желанию
func LoadFromEnv(fpath string) error {
	err := godotenv.Load(fpath)
	if err != nil {
		return err
	}
	return nil
}
