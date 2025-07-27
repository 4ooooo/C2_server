package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	TCPPort string `json:"tcp_port"`
	DNSPort string `json:"dns_port"`
}

var config Config
var TCPServerPort string
var DNSServerPort string

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
	TCPServerPort = ":" + config.TCPPort
	DNSServerPort = ":" + config.DNSPort
	return nil
}
