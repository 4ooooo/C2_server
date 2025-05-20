package server

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Controller 表示与控制端的通信会话
type Controller struct {
	conn         net.Conn
	server       *Server
	reader       *bufio.Reader
	activeClient *Client
}

// NewController 创建新的控制端通信会话
func NewController(conn net.Conn, server *Server) *Controller {
	return &Controller{
		conn:   conn,
		server: server,
		reader: bufio.NewReader(conn),
	}
}

// handleCommands 处理来自控制端的命令
func (c *Controller) handleCommands() {
	defer c.conn.Close()

	for {
		// 发送命令提示符
		c.sendMessage("> ")

		// 读取命令
		cmdStr, err := c.reader.ReadString('\n')
		if err != nil {
			fmt.Println("读取控制端命令失败:", err)
			break
		}

		cmdStr = strings.TrimSpace(cmdStr)
		if cmdStr == "" {
			continue
		}

		// 处理命令
		if cmdStr == "exit" {
			c.sendMessage("断开连接\n")
			break
		} else if cmdStr == "list nodes" {
			c.handleListNodes()
		} else if strings.HasPrefix(cmdStr, "choose ") {
			c.handleChooseNode(cmdStr)
		} else if c.activeClient != nil {
			// 如果已选择客户端，将命令转发给它
			c.handleClientCommand(cmdStr)
		} else {
			c.sendMessage("未知命令或未选择客户端。请先使用 'choose <id>' 选择客户端。\n")
		}
	}
}

// handleListNodes 处理list nodes命令
func (c *Controller) handleListNodes() {
	clients := c.server.ListClients()
	if len(clients) == 0 {
		c.sendMessage("没有客户端连接\n")
		return
	}

	c.sendMessage("已连接的客户端:\n")
	for _, client := range clients {
		c.sendMessage(fmt.Sprintf("%s\n", client.GetInfo()))
	}
}

// handleChooseNode 处理choose命令
func (c *Controller) handleChooseNode(cmdStr string) {
	parts := strings.Split(cmdStr, " ")
	if len(parts) != 2 {
		c.sendMessage("无效的命令格式。使用方法: choose <id>\n")
		return
	}

	id, err := strconv.Atoi(parts[1])
	if err != nil {
		c.sendMessage("无效的客户端ID\n")
		return
	}

	client := c.server.GetClient(id)
	if client == nil {
		c.sendMessage(fmt.Sprintf("未找到ID为 %d 的客户端\n", id))
		return
	}

	c.activeClient = client
	c.sendMessage(fmt.Sprintf("已选择客户端 #%d\n", id))
}

// handleClientCommand 处理发送给客户端的命令
func (c *Controller) handleClientCommand(cmdStr string) {
	result, err := c.activeClient.SendCommand(cmdStr)
	if err != nil {
		c.sendMessage(fmt.Sprintf("命令执行失败: %v\n", err))
		// 如果客户端断开连接，重置当前活动客户端
		if strings.Contains(err.Error(), "断开连接") {
			c.server.RemoveClient(c.activeClient.ID)
			c.activeClient = nil
		}
		return
	}

	// 分块发送结果以确保完整传输
	c.sendMessage(fmt.Sprintf("客户端 #%d 返回结果:\n", c.activeClient.ID))

	// 将结果按行分割并单独发送
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if line != "" {
			// 每行单独发送并添加延迟以确保完整接收
			c.sendMessage(line + "\n")
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// sendMessage 向控制端发送消息，确保完整传输
func (c *Controller) sendMessage(msg string) {
	// 确保消息以换行符结尾
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}

	// 分块发送大消息
	const chunkSize = 1024 // 1KB一块
	messageLength := len(msg)

	for i := 0; i < messageLength; i += chunkSize {
		end := i + chunkSize
		if end > messageLength {
			end = messageLength
		}

		chunk := msg[i:end]
		_, err := c.conn.Write([]byte(chunk))
		if err != nil {
			fmt.Println("向控制端发送消息失败:", err)
			return
		}

		// 短暂延迟确保接收端能处理
		if messageLength > chunkSize {
			time.Sleep(5 * time.Millisecond)
		}
	}
}
