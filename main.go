package main

import (
	"c2_server/server"
	"fmt"
	"log"
)

func main() {
	srv := server.NewServer(":8080")
	fmt.Println("C2服务器启动中...")
	err := srv.Start()
	if err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}
