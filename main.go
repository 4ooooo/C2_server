package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("启动监听失败:", err)
		return
	}
	defer listener.Close()
	fmt.Println("服务器已启动，等待客户端连接...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("接受连接失败:", err)
			continue
		}
		fmt.Println("客户端已连接:", conn.RemoteAddr())
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	serverReader := bufio.NewReader(os.Stdin)
	clientReader := bufio.NewReader(conn)

	for {
		fmt.Print("请输入要发送的命令（或 exit 退出）: ")
		cmdStr, err := serverReader.ReadString('\n')
		if err != nil {
			fmt.Println("读取输入失败:", err)
			break
		}
		if strings.TrimSpace(cmdStr) == "exit" {
			fmt.Println("断开连接")
			break
		}

		// 向客户端发送命令
		_, err = conn.Write([]byte(cmdStr))
		if err != nil {
			fmt.Println("发送命令失败:", err)
			break
		}

		// 读取客户端返回结果（直到遇到 ===END===）
		fmt.Println("客户端返回结果：")
		for {
			line, err := clientReader.ReadString('\n')
			if err != nil {
				fmt.Println("读取客户端返回结果失败:", err)
				return
			}
			if strings.TrimSpace(line) == "===END===" {
				break
			}
			fmt.Print(line)
		}
	}
}
