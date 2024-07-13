package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	nurl "net/url"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/hoshinonyaruko/gensokyo-telegram/Processor"
	"github.com/hoshinonyaruko/gensokyo-telegram/callapi"
	"github.com/hoshinonyaruko/gensokyo-telegram/config"
	"github.com/hoshinonyaruko/gensokyo-telegram/handlers"
	"github.com/hoshinonyaruko/gensokyo-telegram/idmap"
	"github.com/hoshinonyaruko/gensokyo-telegram/images"
	"github.com/hoshinonyaruko/gensokyo-telegram/mylog"
	"github.com/hoshinonyaruko/gensokyo-telegram/server"
	"github.com/hoshinonyaruko/gensokyo-telegram/silk"
	"github.com/hoshinonyaruko/gensokyo-telegram/sys"
	"github.com/hoshinonyaruko/gensokyo-telegram/template"
	"github.com/hoshinonyaruko/gensokyo-telegram/url"
	"github.com/hoshinonyaruko/gensokyo-telegram/webui"
	"github.com/hoshinonyaruko/gensokyo-telegram/wsclient"
	"golang.ngrok.com/ngrok"
	nconfig "golang.ngrok.com/ngrok/config"
)

var msgIdToEchoMap = make(map[int64]string)
var msgIdToEchoMapMutex = &sync.Mutex{}

var wsClients []*wsclient.WebSocketClient

// UserReplyCountMap 用于存储每个用户的默认回复计数
var UserReplyCountMap sync.Map

// 全局正则表达式定义，避免重复编译
var (
	httpUrlImagePattern   = regexp.MustCompile(`\[CQ:image,file=http://(.+?)\]`)
	httpsUrlImagePattern  = regexp.MustCompile(`\[CQ:image,file=https://(.+?)\]`)
	httpUrlRecordPattern  = regexp.MustCompile(`\[CQ:record,file=http://(.+?)\]`)
	httpsUrlRecordPattern = regexp.MustCompile(`\[CQ:record,file=https://(.+?)\]`)
	base64ImagePattern    = regexp.MustCompile(`\[CQ:image,file=base64://(.+?)\]`)
	base64RecordPattern   = regexp.MustCompile(`\[CQ:record,file=base64://(.+?)\]`)
	cqAtPattern           = regexp.MustCompile(`\[CQ:at,qq=\d+\]`)
)

func main() {
	//log.Println(http.ListenAndServe(":80", nil))
	// 定义faststart命令行标志。默认为false。
	fastStart := flag.Bool("faststart", false, "start without initialization if set")
	// 解析命令行参数到定义的标志。
	flag.Parse()
	// 检查是否使用了-faststart参数
	if !*fastStart {
		sys.InitBase() // 如果不是faststart模式，则执行初始化
	}
	if _, err := os.Stat("config.yml"); os.IsNotExist(err) {
		var ip string
		var err error
		// 检查操作系统是否为Android
		if runtime.GOOS == "android" {
			ip = "127.0.0.1"
		} else {
			// 获取内网IP地址
			ip, err = sys.GetLocalIP()
			if err != nil {
				log.Println("Error retrieving the local IP address:", err)
				ip = "127.0.0.1"
			}
		}
		// 将 <YOUR_SERVER_DIR> 替换成实际的内网IP地址 确保初始状态webui能够被访问
		configData := strings.Replace(template.ConfigTemplate, "<YOUR_SERVER_DIR>", ip, -1)

		// 将修改后的配置写入 config.yml
		err = os.WriteFile("config.yml", []byte(configData), 0644)
		if err != nil {
			log.Println("Error writing config.yml:", err)
			return
		}

		log.Println("请配置config.yml然后再次运行.")
		log.Print("按下 Enter 继续...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
		os.Exit(0)
	}
	// 主逻辑
	// 加载配置
	conf, err := config.LoadConfig("config.yml")
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	sys.SetTitle(conf.Settings.Title)
	webuiURL := config.ComposeWebUIURL(conf.Settings.Lotus)     // 调用函数获取URL
	webuiURLv2 := config.ComposeWebUIURLv2(conf.Settings.Lotus) // 调用函数获取URL

	//创建idmap服务器 数据库
	idmap.InitializeDB()
	//创建webui数据库
	webui.InitializeDB()
	defer idmap.CloseDB()
	defer webui.CloseDB()

	// 创建自签名证书
	if config.GetCustomCert() {
		generateCert(conf.Settings.Server_dir)
	}
	// 创建tg的机器人
	tgbotToken := conf.Settings.BotToken
	bot, err := tgbotapi.NewBotAPI(tgbotToken)
	if err != nil {
		log.Printf("Telegram CreatNewBot failed,check your botToken")
		log.Fatal(err)
	}
	// debug模式
	bot.Debug = true
	var u tgbotapi.UpdateConfig
	log.Printf("Authorized on account %s", bot.Self.UserName)

	// 是否使用方便又好用的ngrok 这段代码会改变后续的运行逻辑
	if config.GetUseNgrok() {
		ngrokKey := config.GetNgrokKey()
		// 初始化ngrok
		// Use ngrok to expose the Gin server
		ctx := context.Background()
		ln, err := ngrok.Listen(ctx,
			nconfig.HTTPEndpoint(),
			ngrok.WithAuthtoken(ngrokKey),
		)
		if err != nil {
			log.Println("Ngrok err:", err)
			return
		}
		log.Println("Ingress established at:", ln.URL())
		ngrokURL := ln.URL()
		// Parse the URL to extract the hostname without the protocol
		parsedURL, err := nurl.Parse(ngrokURL)
		if err != nil {
			log.Fatalf("Failed to parse ngrok URL: %v", err)
		}

		hostname := parsedURL.Host
		conf.Settings.WebHookPath = ngrokURL + "/" // Full URL including protocol if required
		conf.Settings.Server_dir = hostname        // Hostname without protocol
		log.Println("new Server_dir:", config.GetServer_dir())
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Println("Error accepting connection:", err)
					return
				}

				log.Println("Accepted connection from", conn.RemoteAddr())

				// 回显接收到的请求信息，直接处理原始的HTTP请求
				go func(c net.Conn) {
					defer c.Close()
					buffer := make([]byte, 4096) // Adjust buffer size as needed
					n, err := c.Read(buffer)
					if err != nil {
						log.Println("Error reading:", err)
						return
					}
					log.Printf("ngrok Received: %s", string(buffer[:n]))

					// Find the start of JSON in the received data
					body := string(buffer[:n]) // Convert buffer to string for processing
					startIndex := strings.Index(body, "\r\n\r\n") + 4
					if startIndex < 4 || startIndex >= len(body) { // Check for valid startIndex
						log.Println("Failed to locate JSON start in the message")
						return
					}
					jsonStr := body[startIndex:]

					var update tgbotapi.Update
					err = json.Unmarshal([]byte(jsonStr), &update)
					if err != nil {
						log.Printf("Error unmarshalling update: %s", err)
						return
					}

					update.IsHttp = 2 // Mark update as received via HTTP

					// Convert the update back to JSON to send to the standard webhook endpoint
					updateJSON, err := json.Marshal(update)
					if err != nil {
						log.Printf("Error marshalling update: %s", err)
						return
					}

					// 根据 lotus 的值选择端口
					var serverPort string
					if !config.GetLotusValue() {
						serverPort = config.GetPortValue()
					} else {
						serverPort = config.GetBackupPort()
					}

					// 本地无法走https
					if serverPort == "443" || serverPort == "8443" {
						// 创建请求到Gin端点的HTTPS客户端
						_, err := http.Post("http://127.0.0.1:444/"+bot.Token, "application/json", bytes.NewBuffer(updateJSON))
						if err != nil {
							log.Printf("Error sending update to webhook endpoint: %s", err)
						}
					} else {
						// 创建请求到Gin端点的HTTP客户端
						_, err := http.Post("http://127.0.0.1:"+serverPort+"/"+bot.Token, "application/json", bytes.NewBuffer(updateJSON))
						if err != nil {
							log.Printf("Error sending update to webhook endpoint: %s", err)
						}
					}

					// 构造HTTP响应 TODO:支持直接返回文字信息的响应,加快ngrok发送的速度
					_, err = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
					if err != nil {
						log.Println("Error writing:", err)
						return
					}
				}(conn)
			}
		}()
	}

	// 长轮询还是webhook
	if !config.GetHttpGetMsg() {
		//创建 webhook
		var wh tgbotapi.WebhookConfig
		webhookPath := conf.Settings.WebHookPath
		//.pem格式
		if config.GetCustomCert() {
			wh, err = tgbotapi.NewWebhookWithCert(webhookPath+bot.Token, tgbotapi.FilePath("cert.pem"))
		} else {
			wh, err = tgbotapi.NewWebhook(webhookPath + bot.Token)
		}

		if err != nil {
			log.Printf("Telegram NewWebhookWithCert failed: %s", err)
		}

		webhookresponse, err := bot.Request(wh)
		if err != nil {
			log.Printf("upload webhook config failed:%s", err)
		}

		log.Printf("Telegram webhookresponse: %v", webhookresponse)

		info, err := bot.GetWebhookInfo()
		if err != nil {
			log.Fatal(err)
		} else {
			log.Printf("Telegram GetWebhookInfo success: %v", info)
		}
		if info.LastErrorDate != 0 {
			log.Printf("Telegram callback failed: %s", info.LastErrorMessage)
		}
	} else {
		// 删除Webhook
		_, err = bot.Request(tgbotapi.DeleteWebhookConfig{})
		if err != nil {
			log.Fatalf("Failed to delete webhook: %v", err)
		}
		lastUpdateID, err := idmap.ReadConfigv2("Telegram", "LastUpdateID")
		if err != nil {
			lastUpdateID = "0"
			log.Printf("Read lastUpdateID failed.%v", err)
		} else {
			log.Printf("lastUpdateID %s.", lastUpdateID)
		}
		intlastUpdateID, err := strconv.Atoi(lastUpdateID)
		if err != nil {
			log.Printf("strconv.Atoi(lastUpdateID) err %v.", err)
		}
		u = tgbotapi.NewUpdate(intlastUpdateID)
		u.Timeout = config.GetMsgTimeOut()
		log.Printf("Telegram Use GetHttpGetMsg Mode.Suggest to use webhook for better performance.")
	}

	botIdStr := strconv.FormatInt(bot.Self.ID, 10)
	config.SetBotID(botIdStr)

	// 启动多个WebSocket客户端的逻辑
	if !allEmpty(conf.Settings.WsAddress) {
		wsClientChan := make(chan *wsclient.WebSocketClient, len(conf.Settings.WsAddress))
		errorChan := make(chan error, len(conf.Settings.WsAddress))
		// 定义计数器跟踪尝试建立的连接数
		attemptedConnections := 0
		for _, wsAddr := range conf.Settings.WsAddress {
			if wsAddr == "" {
				continue // Skip empty addresses
			}
			attemptedConnections++ // 增加尝试连接的计数
			go func(address string) {
				retry := config.GetLaunchReconectTimes()

				wsClient, err := wsclient.NewWebSocketClient(address, botIdStr, retry, bot)
				if err != nil {
					log.Printf("Error creating WebSocketClient for address(连接到反向ws失败) %s: %v\n", address, err)
					errorChan <- err
					return
				}
				wsClientChan <- wsClient
			}(wsAddr)
		}
		// 获取连接成功后的wsClient
		for i := 0; i < attemptedConnections; i++ {
			select {
			case wsClient := <-wsClientChan:
				wsClients = append(wsClients, wsClient)
			case err := <-errorChan:
				log.Printf("Error encountered while initializing WebSocketClient: %v\n", err)
			}
		}

		// 确保所有尝试建立的连接都有对应的wsClient
		if len(wsClients) == 0 {
			log.Println("Error: Not all wsClients are initialized!(反向ws未设置或全部连接失败)")
		} else {
			log.Println("All wsClients are successfully initialized.")
		}
	} else if conf.Settings.EnableWsServer {
		log.Println("只启动正向ws")

	}

	//图片上传 调用次数限制
	rateLimiter := server.NewRateLimiter()
	// 根据 lotus 的值选择端口
	var serverPort string
	if !conf.Settings.Lotus {
		serverPort = conf.Settings.Port
	} else {
		serverPort = conf.Settings.BackupPort
	}
	var r *gin.Engine

	if config.GetDeveloperLog() {
		// 启用开发者模式
		gin.SetMode(gin.DebugMode)
		r = gin.Default()
	} else {
		// 生产模式
		gin.SetMode(gin.ReleaseMode)
		r = gin.New()
		r.Use(gin.Recovery()) // 使用恢复中间件
	}

	// 注册 handler
	if !config.GetHttpGetMsg() {
		r.POST("/"+bot.Token, handleUpdatesGin(bot))
	} else {
		// 长轮询时将获取到的信息转化为本地到本地的webhook从而复用信息处理逻辑
		log.Println("Using Long Polling")
		r.POST("/"+bot.Token, handleUpdatesGin(bot))
		go simulateWebhookFromPolling(bot, u)
	}

	r.GET("/getid", server.GetIDHandler)
	r.GET("/updateport", server.HandleIpupdate)
	r.POST("/uploadpic", server.UploadBase64ImageHandler(rateLimiter))
	r.POST("/uploadrecord", server.UploadBase64RecordHandler(rateLimiter))
	r.Static("/channel_temp", "./channel_temp")

	//webui和它的api
	webuiGroup := r.Group("/webui")
	{
		webuiGroup.GET("/*filepath", webui.CombinedMiddleware())
		webuiGroup.POST("/*filepath", webui.CombinedMiddleware())
		webuiGroup.PUT("/*filepath", webui.CombinedMiddleware())
		webuiGroup.DELETE("/*filepath", webui.CombinedMiddleware())
		webuiGroup.PATCH("/*filepath", webui.CombinedMiddleware())
	}

	//正向http api
	// http_api_address := config.GetHttpAddress()
	// if http_api_address != "" {
	// 	mylog.Println("正向http api启动成功,监听" + http_api_address + "若有需要,请对外放通端口...")
	// 	HttpApiGroup := hr.Group("/")
	// 	{
	// 		HttpApiGroup.GET("/*filepath", httpapi.CombinedMiddleware())
	// 		HttpApiGroup.POST("/*filepath", httpapi.CombinedMiddleware())
	// 		HttpApiGroup.PUT("/*filepath", httpapi.CombinedMiddleware())
	// 		HttpApiGroup.DELETE("/*filepath", httpapi.CombinedMiddleware())
	// 		HttpApiGroup.PATCH("/*filepath", httpapi.CombinedMiddleware())
	// 	}
	// }

	r.POST("/url", url.CreateShortURLHandler)
	r.GET("/url/:shortURL", url.RedirectFromShortURLHandler)

	// Create a logger that writes to stdout, with logFilter filtering the output.
	filteredLogger := log.New(os.Stdout, "INFO: ", log.LstdFlags)
	customLogger := &logFilter{logger: filteredLogger}

	//创建一个http.Server实例（主服务器）
	httpServer := &http.Server{
		Addr:    "0.0.0.0:" + serverPort,
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12, // 设置TLS最小版本
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				// 可以添加更多支持PFS的密码套件
			},
		},
		ErrorLog: log.New(customLogger, "", 0), // Use customLogger for error logging.
	}

	mylog.Printf("gin运行在%v端口", serverPort)
	// 在一个新的goroutine中启动主服务器
	go func() {
		if serverPort == "443" || serverPort == "8443" {
			// 使用HTTPS
			var crtPath, keyPath string
			if config.GetCustomCert() {
				crtPath = "cert.pem"
				keyPath = "key.pem"
			} else {
				crtPath = config.GetCrtPath()
				keyPath = config.GetKeyPath()
			}

			if crtPath == "" || keyPath == "" {
				log.Fatalf("crt or key path is missing for HTTPS")
				return
			}
			if err := httpServer.ListenAndServeTLS(crtPath, keyPath); err != nil && err != http.ErrServerClosed {
				log.Fatalf("listen (HTTPS): %s\n", err)
			}
		} else {
			// 使用HTTP
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("listen: %s\n", err)
			}
		}
	}()

	// 如果主服务器使用443端口，同时在一个新的goroutine中启动444端口的HTTP服务器 todo 更优解
	if serverPort == "443" || serverPort == "8443" {
		go func() {
			// 创建另一个http.Server实例（用于444端口）
			httpServer444 := &http.Server{
				Addr:    "0.0.0.0:444",
				Handler: r,
			}
			// 启动444端口的HTTP服务器
			if err := httpServer444.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("listen (HTTP 444): %s\n", err)
			}
		}()
	}
	// 创建 httpapi 的http server
	// if http_api_address != "" {
	// 	go func() {
	// 		// 创建一个http.Server实例（Http Api服务器）
	// 		httpServerHttpApi := &http.Server{
	// 			Addr:    http_api_address,
	// 			Handler: hr,
	// 		}
	// 		// 使用HTTP
	// 		if err := httpServerHttpApi.ListenAndServe(); err != nil && err != http.ErrServerClosed {
	// 			log.Fatalf("http apilisten: %s\n", err)
	// 		}
	// 	}()
	// }

	// 使用color库输出天蓝色的文本
	cyan := color.New(color.FgCyan)
	cyan.Printf("欢迎来到Gensokyo, 控制台地址: %s\n", webuiURL)
	cyan.Printf("%s\n", template.Logo)
	cyan.Printf("欢迎来到Gensokyo, 公网控制台地址(需开放端口): %s\n", webuiURLv2)
	cyan.Printf("可能需要等待1-2分钟才会收到来自Telegram的webhook事件....")

	// 使用通道来等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 阻塞主线程，直到接收到信号
	<-sigCh

	// 关闭 WebSocket 连接
	// wsClients 是一个 *wsclient.WebSocketClient 的切片
	for _, client := range wsClients {
		err := client.Close()
		if err != nil {
			log.Printf("Error closing WebSocket connection: %v\n", err)
		}
	}

	// 关闭BoltDB数据库
	url.CloseDB()
	idmap.CloseDB()

	// 使用一个5秒的超时优雅地关闭Gin服务器
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}
}

// allEmpty checks if all the strings in the slice are empty.
func allEmpty(addresses []string) bool {
	for _, addr := range addresses {
		if addr != "" {
			return false
		}
	}
	return true
}

// logFilter wraps a log.Logger to filter out specific log messages.
type logFilter struct {
	logger *log.Logger
}

// Write filters out log messages containing "tls: bad record MAC" and forwards the rest to the underlying logger.
func (lf *logFilter) Write(p []byte) (n int, err error) {
	if strings.Contains(string(p), "tls: bad record MAC") {
		// If the log message contains "tls: bad record MAC", ignore it.
		return len(p), nil
	}
	// For all other messages, log them using the underlying logger.
	// Note: We're using Print here to directly log the message without dealing with Output's calldepth.
	lf.logger.Print(string(p))
	return len(p), nil
}

// sendDirectResponse 根据Telegram API的要求构造直接响应
func sendDirectResponse(c *gin.Context, msg tgbotapi.MessageConfig) {
	// 这里需要构造一个符合Telegram期望的响应格式，例如使用sendMessage方法
	log.Printf("sendDirectResponse: %s", msg.Text)
	response := map[string]interface{}{
		"method":  "sendMessage",
		"chat_id": msg.ChatID,
		"text":    msg.Text,
	}
	c.JSON(http.StatusOK, response)
}

// handleUpdatesGin 使用Gin框架处理Telegram Webhook
func handleUpdatesGin(bot *tgbotapi.BotAPI) gin.HandlerFunc {
	return func(c *gin.Context) {
		var update tgbotapi.Update
		if err := c.ShouldBindJSON(&update); err != nil {
			log.Printf("Error decoding update: %s", err)
			// 构建错误响应
			errMsg := map[string]string{"error": err.Error()}
			c.JSON(http.StatusBadRequest, errMsg)
			return
		}

		if update.Message != nil { // 如果收到消息
			log.Printf("[%s] %s", update.Message.From.UserName, update.Message.Text)
			//收到了信息

			msgIdToEchoMapMutex.Lock()
			echo, exists := msgIdToEchoMap[int64(update.Message.MessageID)]
			msgIdToEchoMapMutex.Unlock()
			// 如果msgId不存在，则处理消息
			var err error
			if !exists {
				// 根据配置调用相应的处理函数
				if config.GetGlobalGroupOrPrivate() {
					echo, err = Processor.ProcessGroupMessage(update.Message, wsClients)
					if err != nil {
						log.Printf("处理信息出错:\n%v\n", err)
					}
				} else {
					echo, err = Processor.ProcessC2CMessage(update.Message, wsClients)
					if err != nil {
						log.Printf("处理信息出错:\n%v\n", err)
					}
				}

				// 存储msgId和echo的映射关系
				msgIdToEchoMapMutex.Lock()
				msgIdToEchoMap[int64(update.Message.MessageID)] = echo
				msgIdToEchoMapMutex.Unlock()
			}
			var message *callapi.ActionMessage
			timeout := config.GetTimeOut()
			if config.GetTwoWayEcho() {
				// 发送消息给WS接口，并等待响应
				message, err = wsclient.WaitForActionMessage(echo, time.Duration(timeout)*time.Second) // 使用新的超时时间
				if err != nil {
					log.Printf("Error waiting for action message: %v", err)
					// 处理错误...
					message = DefaultReplyIfNeeded(update.Message.From.UserName)
					if message.Params.Message.(string) == "" {
						log.Printf("默认信息为空,请到config设置,或该用户今日已达到默认回复上限.")
						return
					}
				}
			} else {
				// 发送消息给WS接口，并等待响应
				message, err = wsclient.WaitForGeneralMessage(time.Duration(timeout) * time.Second) // 使用新的超时时间
				if err != nil {
					log.Printf("Error waiting for action message: %v", err)
					// 处理错误...
					message = DefaultReplyIfNeeded(update.Message.From.UserName)
					if message.Params.Message.(string) == "" {
						log.Printf("默认信息为空,请到config设置,或该用户今日已达到默认回复上限.")
						return
					}
				}
			}
			var strmessage string
			// 尝试将message.Params.Message断言为string类型
			if msgStr, ok := message.Params.Message.(string); ok {
				strmessage = msgStr
			} else {
				// 如果不是string，调用parseMessage函数处理
				strmessage = handlers.ParseMessageContent(message.Params.Message)
			}
			// 调用信息处理函数
			msgtype, result, err := ProcessMessage(strmessage, bot, update.Message.Chat.ID, update.IsHttp)
			if err != nil {
				log.Printf("Error ProcessMessage: %v", err)
				response := tgbotapi.NewMessage(update.Message.Chat.ID, "无法处理您的消息")
				sendDirectResponse(c, response)
				return
			}

			if !config.GetSendDirectResponse() {
				//如果SendDirectResponse是false 那么就调用api发信息
				update.IsHttp = 1
			}

			// 1 http长轮询 2 ngrok
			if msgtype == 1 && update.IsHttp != 1 && update.IsHttp != 2 {
				// 如果msgtype是1，直接在Webhook响应中返回信息
				for _, chattable := range result {
					switch msg := chattable.(type) {
					case tgbotapi.MessageConfig:
						sendDirectResponse(c, msg)
						//return // 处理完第一个消息后返回 不返回继续判断是否有要发送的信息
					default:
						log.Printf("Unsupported type for direct Webhook response: %T", msg)
						c.AbortWithStatus(http.StatusInternalServerError)
						return
					}
				}
			} else {
				// 如果不是1，按原有的逻辑发送
				for _, chattable := range result {
					if _, err := bot.Send(chattable); err != nil {
						log.Printf("Error sending reply: %s", err)
					}
				}
				c.Status(http.StatusOK) // 确认收到
			}

			// 在发送完初始消息之后
			if config.GetTwoWayEcho() {
				// 假设echo是与待处理的消息相关联的唯一标识
				messages, err := wsclient.DrainEchoChannel(echo, time.Duration(timeout)*time.Second) // 获取带有echo的通道中的所有剩余信息
				if err != nil {
					log.Printf("Error draining echo channel: %v", err)
				} else {
					for _, msg := range messages {
						// 对每条额外的消息进行处理和发送
						strmessage := handlers.ParseMessageContent(msg.Params.Message)
						_, additionalResults, err := ProcessMessage(strmessage, bot, update.Message.Chat.ID, update.IsHttp)
						if err != nil {
							log.Printf("Error processing additional message: %v", err)
							continue
						}
						for _, chattable := range additionalResults {
							if _, err := bot.Send(chattable); err != nil {
								log.Printf("Error sending additional reply: %s", err)
							}
						}
					}
				}
			} else {
				// 对于通用通道
				messages, err := wsclient.DrainGeneralChannel(time.Duration(timeout) * time.Second) // 获取通用通道中的所有剩余信息
				if err != nil {
					log.Printf("Error draining general channel: %v", err)
				} else {
					for _, msg := range messages {
						// 对每条额外的消息进行处理和发送
						strmessage := handlers.ParseMessageContent(msg.Params.Message)
						_, additionalResults, err := ProcessMessage(strmessage, bot, update.Message.Chat.ID, update.IsHttp)
						if err != nil {
							log.Printf("Error processing additional message: %v", err)
							continue
						}
						for _, chattable := range additionalResults {
							if _, err := bot.Send(chattable); err != nil {
								log.Printf("Error sending additional reply: %s", err)
							}
						}
					}
				}
			}
		}
	}
}

// pollUpdates 长轮询获取更新
func simulateWebhookFromPolling(bot *tgbotapi.BotAPI, u tgbotapi.UpdateConfig) {
	var lastUpdateID int = 0 // 用于跟踪最后处理的更新ID
	updates := bot.GetUpdatesChan(u)
	for update := range updates {
		update.IsHttp = 1
		// 将update转换为JSON
		updateJSON, err := json.Marshal(update)
		if err != nil {
			log.Printf("Error marshalling update: %s", err)
			continue
		}

		// 更新最后处理的更新ID
		lastUpdateID = update.UpdateID

		// 持久化存储最后一个处理过的更新ID
		err = idmap.WriteConfigv2("Telegram", "LastUpdateID", strconv.Itoa(lastUpdateID))
		if err != nil {
			log.Printf("Error saving last update ID: %s", err)
			continue // 处理下一个更新
		}
		// 根据 lotus 的值选择端口
		var serverPort string
		if !config.GetLotusValue() {
			serverPort = config.GetPortValue()
		} else {
			serverPort = config.GetBackupPort()
		}
		// 本地无法走https
		if serverPort == "443" || serverPort == "8443" {
			// 创建请求到Gin端点的HTTPS客户端
			_, err := http.Post("http://127.0.0.1:444/"+bot.Token, "application/json", bytes.NewBuffer(updateJSON))
			if err != nil {
				log.Printf("Error sending update to webhook endpoint: %s", err)
			}

		} else {
			// 创建请求到Gin端点的HTTP客户端
			_, err := http.Post("http://127.0.0.1:"+serverPort+"/"+bot.Token, "application/json", bytes.NewBuffer(updateJSON))
			if err != nil {
				log.Printf("Error sending update to webhook endpoint: %s", err)
			}
		}
	}
}

func generateCert(domain string) {
	// 生成RSA密钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// 创建证书模板
	notBefore := time.Now()
	notAfter := notBefore.Add(3560 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Your Organization"}, // 替换为你的组织名
			CommonName:   domain,                        // 使用指定的域名作为通用名
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain}, // 在此处指定要保护的域名列表
	}

	// 自签名证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	// 保存证书
	certOut, err := os.Create("cert.pem")
	if err != nil {
		panic(err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		panic(err)
	}

	// 保存私钥
	keyOut, err := os.Create("key.pem")
	if err != nil {
		panic(err)
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		panic(err)
	}
}

// DefaultReplyIfNeeded 发送默认回复（如果需要）
func DefaultReplyIfNeeded(fromUserName string) *callapi.ActionMessage {
	// 获取今天的日期字符串
	today := time.Now().Format("2006-01-02")
	userKey := fmt.Sprintf("%s_%s", fromUserName, today)

	// 获取用户今天的回复计数
	value, ok := UserReplyCountMap.Load(userKey)
	var count int
	if ok {
		count = value.(int)
	}

	// 检查是否已经达到每日回复限制
	if count >= config.GetDefaultDailyReplyLimit() {
		// 构造ActionMessage类型的消息
		actionMessage := &callapi.ActionMessage{
			Action: "send_group_msg",
			Params: callapi.ParamsContent{
				Message: "",
			},
		}
		return actionMessage // 达到限制，返回空字符串
	}

	// 未达到限制，增加计数并选择一个默认回复
	count++
	UserReplyCountMap.Store(userKey, count)

	defaultReplies := config.GetDefaultContent()
	if len(defaultReplies) == 0 {
		log.Println("No default content available.")
		// 构造ActionMessage类型的消息
		actionMessage := &callapi.ActionMessage{
			Action: "send_group_msg",
			Params: callapi.ParamsContent{
				Message: "",
			},
		}
		return actionMessage
	}

	// 随机选择一个默认回复发送
	reply := GetRandomReply(defaultReplies)

	// 构造ActionMessage类型的消息
	actionMessage := &callapi.ActionMessage{
		Action: "send_group_msg",
		Params: callapi.ParamsContent{
			Message: reply,
		},
	}

	fmt.Println("发送默认回复:", reply)

	return actionMessage
}

// ProcessMessage 处理信息并归类
func ProcessMessage(input string, bot *tgbotapi.BotAPI, chatID int64, ishttp int) (int, []tgbotapi.Chattable, error) {
	// 检查是否含有base64编码的图片或语音信息
	var err error
	if base64ImagePattern.MatchString(input) || base64RecordPattern.MatchString(input) {
		input, err = processInput(input)
		if err != nil {
			log.Printf("processInput出错:\n%v\n", err)
		}
		log.Printf("处理后的base64编码的图片或语音信息:\n%v\n", input)
	}

	// 纯文本信息处理
	if !httpUrlImagePattern.MatchString(input) && !httpsUrlImagePattern.MatchString(input) && !httpUrlRecordPattern.MatchString(input) && !httpsUrlRecordPattern.MatchString(input) {
		filteredInput := cqAtPattern.ReplaceAllString(input, "")
		message := tgbotapi.NewMessage(chatID, filteredInput)
		return 1, []tgbotapi.Chattable{message}, nil
	}

	// 图片信息处理
	if httpUrlImagePattern.MatchString(input) || httpsUrlImagePattern.MatchString(input) {
		imgChatables, err := processImages(input, bot, chatID, ishttp)
		if err != nil {
			return 0, nil, err
		}
		// 判断是单张图片还是图片组
		messageType := 2
		if len(imgChatables) > 1 {
			messageType = 4 // 假设4代表图片媒体组
		}
		return messageType, imgChatables, nil
	}

	// 语音信息处理
	// 注意：需要根据processVoice的实际实现调整
	if httpUrlRecordPattern.MatchString(input) || httpsUrlRecordPattern.MatchString(input) {
		// 假设processVoice也被调整为返回[]tgbotapi.Chattable, error，并且3代表语音消息
		voiceChatables, err := processVoice(input, bot, chatID)
		if err != nil {
			return 0, nil, err
		}
		return 3, voiceChatables, nil
	}

	return 0, nil, errors.New("unknown message format")
}

// downloadImage 下载图片并返回其字节切片
func downloadImage(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-200 status code")
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// imageToBase64 将图片字节切片转换为Base64编码字符串
func imageToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// processImages 处理图片消息，下载图片，转换为Base64，上传到服务器，发送新URL
// 返回值现在包括两个可能的tgbotapi.Chattable，一个用于图片，另一个用于文本（如果有）
func processImages(input string, bot *tgbotapi.BotAPI, chatID int64, ishttp int) ([]tgbotapi.Chattable, error) {
	var chatables []tgbotapi.Chattable
	allImageUrls := append(httpUrlImagePattern.FindAllStringSubmatch(input, -1), httpsUrlImagePattern.FindAllStringSubmatch(input, -1)...)
	if config.GetHighWay() {
		ishttp = 2
	}
	// 用于存储新的图片URL或直接上传的图片
	var newImageUrls []string
	var directUploads []tgbotapi.Chattable

	for _, match := range allImageUrls {
		var imageUrl string
		if httpUrlImagePattern.MatchString(match[0]) {
			imageUrl = "http://" + match[1]
		} else if httpsUrlImagePattern.MatchString(match[0]) {
			imageUrl = "https://" + match[1]
		}

		imageData, err := downloadImage(imageUrl)
		if err != nil {
			log.Printf("Error downloading image: %s", err)
			continue
		}

		if ishttp == 2 {
			// 直接使用multipart方式上传图片字节
			fileBytes := tgbotapi.FileBytes{Name: "image.jpg", Bytes: imageData}
			photoConfig := tgbotapi.NewPhoto(chatID, fileBytes)
			directUploads = append(directUploads, photoConfig)
		} else {
			// 保持原来的处理逻辑
			base64String := imageToBase64(imageData)
			newUrl, err := images.UploadBase64ImageToServer(base64String)
			if err != nil {
				log.Printf("Error uploading image to server: %s", err)
				continue
			}
			newImageUrls = append(newImageUrls, newUrl)
		}
	}

	// 首先处理直接上传的图片
	chatables = append(chatables, directUploads...)

	// 然后处理通过URL上传的图片
	if len(newImageUrls) > 0 {
		if len(newImageUrls) == 1 {
			photo := tgbotapi.NewPhoto(chatID, tgbotapi.FileURL(newImageUrls[0]))
			chatables = append(chatables, photo)
		} else {
			mediaGroup := tgbotapi.NewMediaGroup(chatID, []interface{}{})
			for _, url := range newImageUrls {
				mediaGroup.Media = append(mediaGroup.Media, tgbotapi.NewInputMediaPhoto(tgbotapi.FileURL(url)))
			}
			chatables = append(chatables, mediaGroup)
		}
	}

	// 处理剩余文本
	remainingText := input
	for _, urlMatch := range allImageUrls {
		remainingText = strings.Replace(remainingText, urlMatch[0], "", -1)
	}
	remainingText = strings.TrimSpace(remainingText)

	if remainingText != "" {
		msg := tgbotapi.NewMessage(chatID, remainingText)
		chatables = append(chatables, msg)
	}

	return chatables, nil
}

// 处理语音消息
func processVoice(input string, bot *tgbotapi.BotAPI, chatID int64) ([]tgbotapi.Chattable, error) {
	var chatables []tgbotapi.Chattable
	var voiceUrls []string
	httpRecordUrls := httpUrlRecordPattern.FindAllStringSubmatch(input, -1)
	httpsRecordUrls := httpsUrlRecordPattern.FindAllStringSubmatch(input, -1)

	for _, match := range httpRecordUrls {
		voiceUrls = append(voiceUrls, match[1]) // No need to prepend "http://" since match already includes it
	}
	for _, match := range httpsRecordUrls {
		voiceUrls = append(voiceUrls, match[1]) // Same for "https://"
	}

	if len(voiceUrls) > 0 {
		// 仅处理第一个语音URL
		voice := tgbotapi.NewVoice(chatID, tgbotapi.FileURL(voiceUrls[0]))
		chatables = append(chatables, voice)
		return chatables, nil // 假设3代表语音消息类型
	}

	return nil, errors.New("no valid voice URL found")
}

// joinUrls 将URLs组合成一个字符串，每个URL占一行
func joinUrls(urls []string) string {
	result := ""
	for _, url := range urls {
		result += url + "\n"
	}
	return result
}

// processInput 处理含有Base64编码的图片和语音信息的字符串
func processInput(input string) (string, error) {
	// 定义正则表达式
	base64ImagePattern := regexp.MustCompile(`\[CQ:image,file=base64://(.+?)\]`)
	base64RecordPattern := regexp.MustCompile(`\[CQ:record,file=base64://(.+?)\]`)

	// 处理Base64编码的图片
	input = processBase64Media(input, base64ImagePattern, images.UploadBase64ImageToServer, "image")

	// 处理Base64编码的语音
	input = processBase64Media(input, base64RecordPattern, images.UploadBase64RecordToServer, "record")

	return input, nil
}

// processBase64Media 处理并替换Base64编码的媒体信息
func processBase64Media(input string, pattern *regexp.Regexp, uploadFunc func(string) (string, error), mediaType string) string {
	matches := pattern.FindAllStringSubmatch(input, -1)
	for _, match := range matches {
		base64Data := match[1] // 获取Base64编码数据
		decodedData, err := base64.StdEncoding.DecodeString(base64Data)
		if err != nil {
			mylog.Printf("Failed to decode base64 data: %v", err)
			continue
		}

		// 特殊处理语音数据
		if mediaType == "record" && !silk.IsAMRorSILK(decodedData) {
			decodedData = silk.EncoderSilk(decodedData)
			mylog.Printf("Audio transcoding")
			//mylog.Printf("不是amr格式但是不转码.")
		} else {
			mylog.Printf("pic or amr")
		}

		// 将解码的数据重新编码为Base64并上传
		encodedData := base64.StdEncoding.EncodeToString(decodedData)
		url, err := uploadFunc(encodedData)
		if err != nil {
			mylog.Printf("Failed to upload base64 data: %v", err)
			continue
		}
		// 根据媒体类型构造替换格式
		var cqFormat string
		if mediaType == "image" {
			cqFormat = `[CQ:image,file=%s]`
		} else if mediaType == "record" {
			cqFormat = `[CQ:record,file=%s]`
		}

		// 替换原始Base64编码信息为URL
		input = strings.Replace(input, match[0], fmt.Sprintf(cqFormat, url), 1)

	}
	return input
}

// GetRandomReply 从提供的回复列表中随机选择一个回复
func GetRandomReply(replies []string) string {
	if len(replies) == 0 {
		return ""
	}
	// 生成一个replies切片长度范围内的随机索引
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(replies))))
	if err != nil {
		// 处理随机数生成过程中的错误
		// 在这里，我们简单地返回空字符串或预设的错误回复
		return ""
	}
	index := nBig.Int64()
	// 返回随机选中的回复
	return replies[index]
}

func createHtmlMessageWithImageLinks(imageUrls []string) string {
	messageText := "<b>Here are the images:</b>\n"
	for _, url := range imageUrls {
		// 将每个URL转换为HTML链接
		messageText += "<a href=\"" + url + "\">Image Link</a>\n"
	}
	return messageText
}
