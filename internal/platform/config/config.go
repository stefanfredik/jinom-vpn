package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	AppEnv     string `mapstructure:"APP_ENV"`
	ListenAddr string `mapstructure:"LISTEN_ADDR"`

	Database DatabaseConfig `mapstructure:",squash"`
	Security SecurityConfig `mapstructure:",squash"`
}

type DatabaseConfig struct {
	Host     string `mapstructure:"DB_HOST"`
	Port     int    `mapstructure:"DB_PORT"`
	User     string `mapstructure:"DB_USER"`
	Password string `mapstructure:"DB_PASSWORD"`
	Name     string `mapstructure:"DB_NAME"`
	SSLMode  string `mapstructure:"DB_SSL_MODE"`
}

type SecurityConfig struct {
	MasterKey string `mapstructure:"MASTER_KEY"`
	APIKey    string `mapstructure:"API_KEY"`
}

func LoadConfig(path string) *Config {
	if path != "" {
		viper.SetConfigFile(path)
	}
	viper.AutomaticEnv()

	viper.SetDefault("APP_ENV", "development")
	viper.SetDefault("LISTEN_ADDR", ":8090")
	viper.SetDefault("DB_HOST", "localhost")
	viper.SetDefault("DB_PORT", 5432)
	viper.SetDefault("DB_USER", "jinom")
	viper.SetDefault("DB_PASSWORD", "jinom")
	viper.SetDefault("DB_NAME", "jinom_nms")
	viper.SetDefault("DB_SSL_MODE", "disable")
	viper.SetDefault("MASTER_KEY", "")
	viper.SetDefault("API_KEY", "")

	_ = viper.BindEnv("APP_ENV")
	_ = viper.BindEnv("LISTEN_ADDR")
	_ = viper.BindEnv("DB_HOST")
	_ = viper.BindEnv("DB_PORT")
	_ = viper.BindEnv("DB_USER")
	_ = viper.BindEnv("DB_PASSWORD")
	_ = viper.BindEnv("DB_NAME")
	_ = viper.BindEnv("DB_SSL_MODE")
	_ = viper.BindEnv("MASTER_KEY")
	_ = viper.BindEnv("API_KEY")

	_ = viper.ReadInConfig()

	var cfg Config
	_ = viper.Unmarshal(&cfg)
	return &cfg
}
