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

// ProcessGroupMessage 处理群组消息
func ProcessGroupMessage(data *tgbotapi.Message, Wsclient []*wsclient.WebSocketClient) (echoreturn string, err error) {
	// 获取s
	s := data.MessageID

	// 转换appid
	AppIDString := config.GetBotID()

	// 构造echo
	echostr := AppIDString + "_" + strconv.Itoa(s)
	var userid64 int64
	var GroupID64 int64

	// 映射str的GroupID到int
	GroupID64 = data.Chat.ID

	// 映射str的userid到int
	userid64 = data.From.ID

	selfid := config.ExtractAndTruncateDigits(AppIDString)

	id64, err := strconv.ParseInt(selfid, 10, 64)
	if err != nil {
		// 如果转换失败，处理错误，例如打印错误信息
		fmt.Println("Error converting selfid to int64:", err)
		// 可能需要返回或处理错误
	}

	// 转换at
	// messageText := handlers.RevertTransformedText(data, "group", p.Api, p.Apiv2, GroupID64, userid64, config.GetWhiteEnable(4))
	// if messageText == "" {
	// 	mylog.Printf("信息被自定义黑白名单拦截")

	// }
	//群没有at,但用户可以选择加一个
	// if config.GetAddAtGroup() {
	// 	messageText = "[CQ:at,qq=" + config.GetAppIDStr() + "] " + messageText
	// }
	//框架内指令
	//p.HandleFrameworkCommand(messageText, data, "group")
	messageText := data.Text
	// 如果在Array模式下, 则处理Message为Segment格式
	var segmentedMessages interface{} = messageText
	if config.GetArrayValue() {
		segmentedMessages = handlers.ConvertToSegmentedMessage(messageText)
	}
	var IsBindedUserId, IsBindedGroupId bool
	// if config.GetHashIDValue() {
	// 	IsBindedUserId = idmap.CheckValue(data.Author.ID, userid64)
	// 	IsBindedGroupId = idmap.CheckValue(data.GroupID, GroupID64)
	// } else {
	// 	IsBindedUserId = idmap.CheckValuev2(userid64)
	// 	IsBindedGroupId = idmap.CheckValuev2(GroupID64)
	// }
	groupMsg := OnebotGroupMessage{
		RawMessage:  messageText,
		Message:     segmentedMessages,
		MessageID:   123,
		GroupID:     GroupID64,
		MessageType: "group",
		PostType:    "message",
		SelfID:      id64,
		UserID:      userid64,
		Sender: Sender{
			UserID: userid64,
			Sex:    "0",
			Age:    0,
			Area:   "0",
			Level:  "0",
		},
		SubType: "normal",
		Time:    time.Now().Unix(),
	}
	//增强配置
	if !config.GetNativeOb11() {
		groupMsg.RealMessageType = "group"
		groupMsg.IsBindedUserId = IsBindedUserId
		groupMsg.IsBindedGroupId = IsBindedGroupId
		// if IsBindedUserId {
		// 	//groupMsg.Avatar, _ = GenerateAvatarURL(userid64)
		// }
	}
	//根据条件判断是否增加nick和card
	var CaN = config.GetCardAndNick()
	if CaN != "" {
		groupMsg.Sender.Nickname = CaN
		groupMsg.Sender.Card = CaN
	}
	// 根据条件判断是否添加Echo字段
	if config.GetTwoWayEcho() {
		groupMsg.Echo = echostr
		//用向应用端(如果支持)发送echo,来确定客户端的send_msg对应的触发词原文
		echo.AddMsgIDv3(AppIDString, echostr, messageText)
	}
	// 获取MasterID数组
	masterIDs := config.GetMasterID()

	// 判断userid64是否在masterIDs数组里
	isMaster := false
	for _, id := range masterIDs {
		if strconv.FormatInt(userid64, 10) == id {
			isMaster = true
			break
		}
	}

	// 根据isMaster的值为groupMsg的Sender赋值role字段
	if isMaster {
		groupMsg.Sender.Role = "owner"
	} else {
		groupMsg.Sender.Role = "member"
	}

	// 调试
	PrintStructWithFieldNames(groupMsg)

	// Convert OnebotGroupMessage to map and send
	groupMsgMap := structToMap(groupMsg)
	//上报信息到onebotv11应用端(正反ws)
	BroadcastMessageToAll(groupMsgMap, Wsclient)
	return echostr, err
}
