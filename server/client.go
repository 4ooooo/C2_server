package server

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Client 表示连接到服务器的客户端
type Client struct {
	ID          int
	conn        net.Conn
	reader      *bufio.Reader
	writerMu    sync.Mutex
	isConnected bool
}

// NewClient 创建新的客户端实例
func NewClient(id int, conn net.Conn) *Client {
	return &Client{
		ID:          id,
		conn:        conn,
		reader:      bufio.NewReader(conn),
		isConnected: true,
	}
}

// Start 开始客户端处理
func (c *Client) Start() {
	defer func() {
		c.isConnected = false
		c.conn.Close()
	}()

	// 保持连接但不主动处理，等待命令
	for {
		if !c.isConnected {
			return
		}

		// 简单的心跳检测逻辑
		time.Sleep(30 * time.Second)

		// 可以在这里添加心跳检测代码
		// ...
	}
}

// SendCommand 向客户端发送命令并获取响应
func (c *Client) SendCommand(cmd string) (string, error) {
	if !c.isConnected {
		return "", fmt.Errorf("客户端 #%d 已断开连接", c.ID)
	}

	// 设置超时以防止永久阻塞
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{}) // 恢复无超时

	// 发送命令
	c.writerMu.Lock()
	_, err := c.conn.Write([]byte(cmd + "\n"))
	c.writerMu.Unlock()

	if err != nil {
		c.isConnected = false
		return "", fmt.Errorf("发送命令失败: %w", err)
	}

	// 从客户端读取响应直到遇到结束标记
	var result strings.Builder
	buffer := make([]byte, 4096)
	endMarker := "===END==="

	for {
		n, err := c.reader.Read(buffer)
		if err != nil {
			c.isConnected = false
			return result.String(), fmt.Errorf("读取响应失败: %w", err)
		}

		chunk := string(buffer[:n])
		result.WriteString(chunk)

		// 检查是否包含结束标记
		if strings.Contains(chunk, endMarker) {
			// 移除结束标记
			resultStr := strings.Replace(result.String(), endMarker, "", 1)
			return strings.TrimSpace(resultStr), nil
		}
	}
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
