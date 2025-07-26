package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	Port string `json:"port"`
}

var config Config
var ServerPort string

const configFilePath = "config.json"

func Config_Init() error {
	file, err := os.Open(configFilePath)
	if err != nil {
		return err
	}
	defer file.Close()
	err = json.NewDecoder(file).Decode(&config)
	if err != nil {
		return err
	}
	ServerPort = ":" + string(config.Port)
	return nil
}
