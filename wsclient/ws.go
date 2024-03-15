package wsclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/gorilla/websocket"
	"github.com/hoshinonyaruko/gensokyo-telegram/callapi"
	"github.com/hoshinonyaruko/gensokyo-telegram/config"
	"github.com/hoshinonyaruko/gensokyo-telegram/mylog"
)

var (
	// echoToChanMap 用于存储期待特定 echo 值的消息的通道
	echoToChanMap = make(map[string]chan callapi.ActionMessage)
	// generalChan 用于处理那些echo值不是字符串的消息
	generalChan = make(chan callapi.ActionMessage, 10)
	mapMutex    sync.Mutex
)

type WebSocketClient struct {
	conn           *websocket.Conn
	BotApi         *tgbotapi.BotAPI
	botID          string
	urlStr         string
	cancel         context.CancelFunc
	mutex          sync.Mutex // 用于同步写入和重连操作的互斥锁
	isReconnecting bool
	sendFailures   []map[string]interface{} // 存储失败的消息

}

// 发送json信息给onebot应用端
func (client *WebSocketClient) SendMessage(message map[string]interface{}) error {
	client.mutex.Lock()         // 在写操作之前锁定
	defer client.mutex.Unlock() // 确保在函数返回时解锁

	msgBytes, err := json.Marshal(message)
	if err != nil {
		mylog.Println("Error marshalling message:", err)
		return err
	}

	err = client.conn.WriteMessage(websocket.TextMessage, msgBytes)
	if err != nil {
		mylog.Println("Error sending message:", err)
		// 发送失败，将消息添加到切片
		client.sendFailures = append(client.sendFailures, message)
		return err
	}

	return nil
}

// 处理onebotv11应用端发来的信息
func (client *WebSocketClient) handleIncomingMessages(ctx context.Context, cancel context.CancelFunc) {
	for {
		_, msg, err := client.conn.ReadMessage()
		if err != nil {
			mylog.Println("WebSocket connection closed:", err)
			cancel() // 取消心跳 goroutine
			if !client.isReconnecting {
				go client.Reconnect()
			}
			return // 退出循环，不再尝试读取消息
		}

		go client.recvMessage(msg)
	}
}

// 断线重连
func (client *WebSocketClient) Reconnect() {
	client.isReconnecting = true

	addresses := config.GetWsAddress()
	tokens := config.GetWsToken()

	var token string
	for index, address := range addresses {
		if address == client.urlStr && index < len(tokens) {
			token = tokens[index]
			break
		}
	}

	// 检查URL中是否有access_token参数
	mp := getParamsFromURI(client.urlStr)
	if val, ok := mp["access_token"]; ok {
		token = val
	}

	headers := http.Header{
		"User-Agent":    []string{"CQHttp/4.15.0"},
		"X-Client-Role": []string{"Universal"},
		"X-Self-ID":     []string{client.botID},
	}

	if token != "" {
		headers["Authorization"] = []string{"Token " + token}
	}
	mylog.Printf("准备使用token[%s]重新连接到[%s]\n", token, client.urlStr)
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
	}

	var conn *websocket.Conn
	var err error

	maxRetryAttempts := config.GetReconnecTimes()
	retryCount := 0
	for {
		mylog.Println("Dialing URL:", client.urlStr)
		conn, _, err = dialer.Dial(client.urlStr, headers)
		if err != nil {
			retryCount++
			if retryCount > maxRetryAttempts {
				mylog.Printf("Exceeded maximum retry attempts for WebSocket[%v]: %v\n", client.urlStr, err)
				return
			}
			mylog.Printf("Failed to connect to WebSocket[%v]: %v, retrying in 5 seconds...\n", client.urlStr, err)
			time.Sleep(5 * time.Second) // sleep for 5 seconds before retrying
		} else {
			mylog.Printf("Successfully connected to %s.\n", client.urlStr) // 输出连接成功提示
			break                                                          // successfully connected, break the loop
		}
	}
	// 复用现有的client完成重连
	client.conn = conn
	// 使用strconv.ParseUint将字符串转换为uint64
	selfID, err := strconv.ParseUint(client.botID, 10, 64)
	if err != nil {
		log.Printf("Error converting botID to uint64: %v", err)
		// 在这里处理错误，例如返回或设置selfID为默认值
	}
	// 再次发送元事件
	message := map[string]interface{}{
		"meta_event_type": "lifecycle",
		"post_type":       "meta_event",
		"self_id":         selfID,
		"sub_type":        "connect",
		"time":            int(time.Now().Unix()),
	}

	mylog.Printf("Message: %+v\n", message)

	err = client.SendMessage(message)
	if err != nil {
		// handle error
		mylog.Printf("Error sending message: %v\n", err)
	}

	//退出老的sendHeartbeat和handleIncomingMessages
	client.cancel()

	// Starting goroutine for heartbeats and another for listening to messages
	ctx, cancel := context.WithCancel(context.Background())

	client.cancel = cancel
	heartbeatinterval := config.GetHeartBeatInterval()
	go client.sendHeartbeat(ctx, client.botID, heartbeatinterval)
	go client.handleIncomingMessages(ctx, cancel)

	defer func() {
		client.isReconnecting = false
	}()

	mylog.Printf("Successfully reconnected to WebSocket.")

}

// 处理发送失败的消息
func (client *WebSocketClient) processFailedMessages() {
	for _, failedMessage := range client.sendFailures {
		// 尝试重新发送消息
		err := client.SendMessage(failedMessage)
		if err != nil {
			mylog.Printf("Error resending message: %v\n", err)
		}
	}
	// 清空失败消息列表
	client.sendFailures = []map[string]interface{}{}
}

// 处理信息,调用腾讯api
// recvMessage 处理接收到的消息
func (client *WebSocketClient) recvMessage(msg []byte) {
	var message callapi.ActionMessage
	err := json.Unmarshal(msg, &message)
	if err != nil {
		mylog.Printf("Error unmarshalling message: %v, Original message: %s", err, string(msg))
		return
	}
	mylog.Println("Received from onebotv11 server:", TruncateMessage(message, 800))

	// 判断Action是否以"send"开头
	if !strings.HasPrefix(message.Action, "send") {
		// 如果不是以"send"开头，记录日志并返回
		mylog.Printf("Action '%s' is not supported, ignored.", message.Action)
		client.respondToAction(message.Action, message.Echo)
		return
	}

	mapMutex.Lock()
	defer mapMutex.Unlock()

	// 检查是否启用了双向Echo模式
	twoWayEchoEnabled := config.GetTwoWayEcho()

	if !twoWayEchoEnabled {
		// 如果双向Echo未启用，所有消息都发送到通用通道
		generalChan <- message
		return // 早期返回，避免执行后续逻辑
	}

	// 如果双向Echo启用，根据echo的值处理消息
	echoValue, ok := message.Echo.(string)
	if !ok {
		// 如果echo不是字符串，将消息发送到通用通道
		generalChan <- message
	} else {
		if ch, ok := echoToChanMap[echoValue]; ok {
			// 如果找到匹配的信道，则发送消息
			ch <- message
			// 从映射中移除已处理的echo
			delete(echoToChanMap, echoValue)
		}
	}
}

// WaitForActionMessage 等待特定echo值的消息或超时
func WaitForActionMessage(echo string, timeout time.Duration) (*callapi.ActionMessage, error) {
	ch := make(chan callapi.ActionMessage, 1)

	mapMutex.Lock()
	echoToChanMap[echo] = ch
	mapMutex.Unlock()

	select {
	case msg := <-ch:
		return &msg, nil
	case <-time.After(timeout):
		mapMutex.Lock()
		delete(echoToChanMap, echo)
		mapMutex.Unlock()
		return nil, fmt.Errorf("timeout waiting for message with echo %s", echo)
	}
}

func WaitForGeneralMessage(timeout time.Duration) (*callapi.ActionMessage, error) {
	select {
	case msg := <-generalChan:
		// 成功从通用通道接收到消息
		return &msg, nil
	case <-time.After(timeout):
		// 超时等待通用消息
		return nil, fmt.Errorf("timeout waiting for general message")
	}
}

func DrainGeneralChannel(timeout time.Duration) ([]callapi.ActionMessage, error) {
	var messages []callapi.ActionMessage
	timeoutChan := time.After(timeout) // 设置超时通道

	for {
		select {
		case msg := <-generalChan:
			messages = append(messages, msg)
		case <-timeoutChan:
			// 超时后返回已收集到的消息
			return messages, nil
		default:
			// 如果通道当前为空，但还未到超时时间，避免密集轮询
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func DrainEchoChannel(echo string, timeout time.Duration) ([]callapi.ActionMessage, error) {
	var messages []callapi.ActionMessage

	mapMutex.Lock()
	ch, ok := echoToChanMap[echo]
	mapMutex.Unlock()

	if !ok {
		return nil, fmt.Errorf("no channel found for echo %s", echo)
	}

	timeoutChan := time.After(timeout) // 设置超时通道

	for {
		select {
		case msg := <-ch:
			messages = append(messages, msg)
		case <-timeoutChan:
			// 超时后返回已收集到的消息
			return messages, nil
		default:
			// 如果通道当前为空，但还未到超时时间，避免密集轮询
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// 截断信息
func TruncateMessage(message callapi.ActionMessage, maxLength int) string {
	paramsStr, err := json.Marshal(message.Params)
	if err != nil {
		return "Error marshalling Params for truncation."
	}

	// Truncate Params if its length exceeds maxLength
	truncatedParams := string(paramsStr)
	if len(truncatedParams) > maxLength {
		truncatedParams = truncatedParams[:maxLength] + "..."
	}

	return fmt.Sprintf("Action: %s, Params: %s, Echo: %v", message.Action, truncatedParams, message.Echo)
}

// 发送心跳包
func (client *WebSocketClient) sendHeartbeat(ctx context.Context, botID string, heartbeatinterval int) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(heartbeatinterval) * time.Second):
			// 使用strconv.ParseUint将字符串转换为uint64
			selfID, err := strconv.ParseUint(botID, 10, 64)
			if err != nil {
				log.Printf("Error converting botID to uint64: %v", err)
				// 在这里处理错误，例如返回或设置selfID为默认值
			}
			message := map[string]interface{}{
				"post_type":       "meta_event",
				"meta_event_type": "heartbeat",
				"time":            int(time.Now().Unix()),
				"self_id":         selfID,
				"status": map[string]interface{}{
					"app_enabled":     true,
					"app_good":        true,
					"app_initialized": true,
					"good":            true,
					"online":          true,
					"plugins_good":    nil,
					"stat": map[string]int{
						"packet_received":   34933,
						"packet_sent":       8513,
						"packet_lost":       0,
						"message_received":  24674,
						"message_sent":      1663,
						"disconnect_times":  0,
						"lost_times":        0,
						"last_message_time": int(time.Now().Unix()) - 10, // 假设最后一条消息是10秒前收到的
					},
				},
				"interval": 10000, // 以毫秒为单位
			}
			client.SendMessage(message)
			// 重发失败的消息
			client.processFailedMessages()
		}
	}
}

// NewWebSocketClient 创建 WebSocketClient 实例，接受 WebSocket URL、botID 和 core.Context 指针
func NewWebSocketClient(urlStr string, botID string, maxRetryAttempts int) (*WebSocketClient, error) {
	addresses := config.GetWsAddress()
	tokens := config.GetWsToken()

	var token string
	for index, address := range addresses {
		if address == urlStr && index < len(tokens) {
			token = tokens[index]
			break
		}
	}

	// 检查URL中是否有access_token参数
	mp := getParamsFromURI(urlStr)
	if val, ok := mp["access_token"]; ok {
		token = val
	}

	headers := http.Header{
		"User-Agent":    []string{"CQHttp/4.15.0"},
		"X-Client-Role": []string{"Universal"},
		"X-Self-ID":     []string{botID},
	}

	if token != "" {
		headers["Authorization"] = []string{"Token " + token}
	}
	mylog.Printf("准备使用token[%s]连接到[%s]\n", token, urlStr)
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
	}

	var conn *websocket.Conn
	var err error

	retryCount := 0
	for {
		mylog.Println("Dialing URL:", urlStr)
		conn, _, err = dialer.Dial(urlStr, headers)
		if err != nil {
			retryCount++
			if retryCount > maxRetryAttempts {
				mylog.Printf("Exceeded maximum retry attempts for WebSocket[%v]: %v\n", urlStr, err)
				return nil, err
			}
			mylog.Printf("Failed to connect to WebSocket[%v]: %v, retrying in 5 seconds...\n", urlStr, err)
			time.Sleep(5 * time.Second) // sleep for 5 seconds before retrying
		} else {
			mylog.Printf("Successfully connected to %s.\n", urlStr) // 输出连接成功提示
			break                                                   // successfully connected, break the loop
		}
	}
	client := &WebSocketClient{
		conn:         conn,
		botID:        botID,
		urlStr:       urlStr,
		sendFailures: []map[string]interface{}{},
	}

	// 使用strconv.ParseUint将字符串转换为uint64
	selfID, err := strconv.ParseUint(botID, 10, 64)
	if err != nil {
		log.Printf("Error converting botID to uint64: %v", err)
		// 在这里处理错误，例如返回或设置selfID为默认值
	}

	// Sending initial message similar to your setupB function
	message := map[string]interface{}{
		"meta_event_type": "lifecycle",
		"post_type":       "meta_event",
		"self_id":         selfID,
		"sub_type":        "connect",
		"time":            int(time.Now().Unix()),
	}

	mylog.Printf("Message: %+v\n", message)

	err = client.SendMessage(message)
	if err != nil {
		// handle error
		mylog.Printf("Error sending message: %v\n", err)
	}

	// Starting goroutine for heartbeats and another for listening to messages
	ctx, cancel := context.WithCancel(context.Background())

	client.cancel = cancel
	heartbeatinterval := config.GetHeartBeatInterval()
	go client.sendHeartbeat(ctx, botID, heartbeatinterval)
	go client.handleIncomingMessages(ctx, cancel)

	return client, nil
}

func (ws *WebSocketClient) Close() error {
	ws.mutex.Lock()
	defer ws.mutex.Unlock()
	return ws.conn.Close()
}

// getParamsFromURI 解析给定URI中的查询参数，并返回一个映射（map）
func getParamsFromURI(uriStr string) map[string]string {
	params := make(map[string]string)

	u, err := url.Parse(uriStr)
	if err != nil {
		mylog.Printf("Error parsing the URL: %v\n", err)
		return params
	}

	// 遍历查询参数并将其添加到返回的映射中
	for key, values := range u.Query() {
		if len(values) > 0 {
			params[key] = values[0] // 如果一个参数有多个值，这里只选择第一个。可以根据需求进行调整。
		}
	}

	return params
}

// respondToAction 根据action类型构造并发送响应消息
func (client *WebSocketClient) respondToAction(action string, echo interface{}) {
	var response map[string]interface{}

	switch action {
	case "get_group_list":
		response = make(map[string]interface{})
		data := make([]map[string]interface{}, 1) // 示例仅创建一个元素的数组
		for i := range data {
			data[i] = map[string]interface{}{
				"group_create_time": "0",
				"group_id":          "868858989",
				"group_level":       "0",
				"group_memo":        "",
				"group_name":        "可爱red",
				"max_member_count":  "3000",
				"member_count":      "1800",
			}
		}
		response["data"] = data
		response["message"] = ""
		response["retcode"] = 0
		response["status"] = "ok"
		response["echo"] = echo

	case "get_login_info":
		wxappid := config.GetBotID()
		wxappidintStr := config.ExtractAndTruncateDigits(wxappid)
		// 将字符串转换为int
		wxappidint, err := strconv.Atoi(wxappidintStr)
		if err != nil {
			// 处理可能的错误
			mylog.Printf("Error converting wxappidint to int: %v", err)
			return
		}
		response = map[string]interface{}{
			"data": map[string]interface{}{
				"nickname": "早苗",
				"user_id":  wxappidint,
			},
			"message": "",
			"retcode": 0,
			"status":  "ok",
			"echo":    echo,
		}

	case "get_guild_service_profile":
		response = map[string]interface{}{
			"data": map[string]interface{}{
				"nickname": "",
				"tiny_id":  0,
			},
			"message": "",
			"retcode": 0,
			"status":  "ok",
			"echo":    echo,
		}

	case "get_online_clients":
		response = map[string]interface{}{
			"data": map[string]interface{}{
				"clients": []interface{}{}, // 创建一个空的clients数组
				"tiny_id": 0,
			},
			"message": "",
			"retcode": 0,
			"status":  "ok",
			"echo":    echo,
			"clients": []interface{}{}, // 根据描述，这可能是多余的，除非您有特定需求
		}

	case "get_version_info":
		response = map[string]interface{}{
			"data": map[string]interface{}{
				"app_full_name":              "go-cqhttp-v1.0.0_windows_amd64-go1.20.2",
				"app_name":                   "go-cqhttp",
				"app_version":                "v1.0.0",
				"coolq_directory":            "",
				"coolq_edition":              "pro",
				"go-cqhttp":                  true,
				"plugin_build_configuration": "release",
				"plugin_build_number":        99,
				"plugin_version":             "4.15.0",
				"protocol_name":              4,
				"protocol_version":           "v11",
				"runtime_os":                 "windows",
				"runtime_version":            "go1.20.2",
				"version":                    "v1.0.0",
			},
			"message": "",
			"retcode": 0,
			"status":  "ok",
			"echo":    echo,
		}

	case "get_friend_list":
		friends := []map[string]interface{}{
			{"nickname": "小狐狸", "remark": "", "user_id": "2022717137"},
			// 添加更多好友信息...
		}
		response = map[string]interface{}{
			"data":    friends,
			"message": "",
			"retcode": 0,
			"status":  "ok",
			"echo":    echo,
		}

	case "get_guild_list":
		data := []map[string]interface{}{}
		// 假设我们要添加一个示例公会信息，实际应用中这部分可能需要从数据库或其他数据源动态获取
		for i := 0; i < 1; i++ { // 示例仅添加一个公会
			data = append(data, map[string]interface{}{
				"guild_id":         "0",         // 公会ID示例值
				"guild_name":       "868858989", // 公会名称示例值
				"guild_display_id": "868858989", // 公会显示ID示例值
			})
		}
		response = map[string]interface{}{
			"data":    data,
			"message": "",
			"retcode": 0,
			"status":  "ok",
			"echo":    echo,
		}

	case "get_guild_channel_list":
		// 这里示例不具体填充data数组中的频道信息，假设响应需要的是一个空的频道列表
		response = map[string]interface{}{
			"data":    []interface{}{}, // 创建一个空的频道列表
			"message": "",
			"retcode": 0,
			"status":  "ok",
			"echo":    echo,
		}

	default:
		mylog.Printf("Action '%s' is not supported, ignored.", action)
		return
	}

	err := client.SendMessage(response)
	if err != nil {
		mylog.Println("Error sending message:", err)
		return
	}

	mylog.Printf("Responded to action '%s' with: %v", action, response)
}
