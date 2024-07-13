// 处理收到的信息事件
package Processor

import (
	"fmt"
	"strconv"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/hoshinonyaruko/gensokyo-telegram/config"
	"github.com/hoshinonyaruko/gensokyo-telegram/echo"
	"github.com/hoshinonyaruko/gensokyo-telegram/handlers"
	"github.com/hoshinonyaruko/gensokyo-telegram/wsclient"
)

// ProcessC2CMessage 处理C2C消息 群私聊
func ProcessC2CMessage(data *tgbotapi.Message, Wsclient []*wsclient.WebSocketClient) (echoreturn string, err error) {
	// 打印data结构体
	PrintStructWithFieldNames(data)

	// 从私信中提取必要的信息 这是测试回复需要用到
	//recipientID := data.Author.ID
	//ChannelID := data.ChannelID
	//sourece是源头频道
	//GuildID := data.GuildID

	//获取当前的s值 当前ws连接所收到的信息条数
	s := data.MessageID

	// 直接转换成ob11私信

	AppIDString := config.GetBotID()
	echostr := AppIDString + "_" + strconv.Itoa(s)

	//将真实id转为int userid64
	userid64 := data.From.ID

	selfid := config.ExtractAndTruncateDigits(AppIDString)

	id64, err := strconv.ParseInt(selfid, 10, 64)
	if err != nil {
		// 如果转换失败，处理错误，例如打印错误信息
		fmt.Println("Error converting selfid to int64:", err)
		// 可能需要返回或处理错误
	}

	//收到私聊信息调用的具体还原步骤
	//1,idmap还原真实userid,
	//发信息使用的是userid

	//转换at
	// messageText := handlers.RevertTransformedText(data, "group_private", p.Api, p.Apiv2, userid64, userid64, config.GetWhiteEnable(5))
	// if messageText == "" {
	// 	mylog.Printf("信息被自定义黑白名单拦截")
	// 	return nil
	// }
	//框架内指令
	//p.HandleFrameworkCommand(messageText, data, "group_private")

	messageText := data.Text
	//如果在Array模式下, 则处理Message为Segment格式
	var segmentedMessages interface{} = messageText
	if config.GetArrayValue() {
		segmentedMessages = handlers.ConvertToSegmentedMessage(messageText)
	}
	var IsBindedUserId bool

	// 将chatid和msgid绑定
	echo.AddMappingMsgIDtoChatID(data.MessageID, userid64)

	privateMsg := OnebotPrivateMessage{
		RawMessage:  messageText,
		Message:     segmentedMessages,
		MessageID:   data.MessageID,
		MessageType: "private",
		PostType:    "message",
		SelfID:      id64,
		UserID:      userid64,
		Sender: PrivateSender{
			Nickname: "", //这个不支持,但加机器人好友,会收到一个事件,可以对应储存获取,用idmaps可以做到.
			UserID:   userid64,
		},
		SubType: "friend",
		Time:    time.Now().Unix(),
	}
	if !config.GetNativeOb11() {
		privateMsg.RealMessageType = "group_private"
		privateMsg.IsBindedUserId = IsBindedUserId
		// if IsBindedUserId {
		// 	//privateMsg.Avatar, _ = GenerateAvatarURL(userid64)
		// }
	}
	// 根据条件判断是否添加Echo字段
	if config.GetTwoWayEcho() {
		privateMsg.Echo = echostr
		//用向应用端(如果支持)发送echo,来确定客户端的send_msg对应的触发词原文
		echo.AddMsgIDv3(AppIDString, echostr, messageText)
	}

	// 调试
	PrintStructWithFieldNames(privateMsg)

	// Convert OnebotGroupMessage to map and send
	privateMsgMap := structToMap(privateMsg)
	//上报信息到onebotv11应用端(正反ws)
	BroadcastMessageToAll(privateMsgMap, Wsclient)
	return echostr, err
}
