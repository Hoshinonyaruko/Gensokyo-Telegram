package echo

import (
	"strconv"
	"sync"
	"time"
)

type messageRecord struct {
	messageID string
	timestamp time.Time
}

type messageStore struct {
	mu      sync.RWMutex
	records map[string][]messageRecord
}

var instance *messageStore
var once sync.Once

// 惰性初始化
func initInstance() *messageStore {
	once.Do(func() {
		instance = &messageStore{
			records: make(map[string][]messageRecord),
		}
	})
	return instance
}

// AddLazyMessageId 添加 message_id 和它的时间戳到指定群号
func AddLazyMessageId(groupID, messageID string, timestamp time.Time) {
	store := initInstance()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records[groupID] = append(store.records[groupID], messageRecord{messageID: messageID, timestamp: timestamp})
}

// AddLazyMessageId 添加 message_id 和它的时间戳到指定群号
func AddLazyMessageIdv2(groupID, userID, messageID string, timestamp time.Time) {
	store := initInstance()
	store.mu.Lock()
	defer store.mu.Unlock()
	key := groupID + "." + userID
	store.records[key] = append(store.records[key], messageRecord{messageID: messageID, timestamp: timestamp})
}

// 通过group_id获取类型
func GetMessageTypeByGroupidv2(appID string, GroupID interface{}) string { //2
	// 从appID和userID生成key
	var GroupIDStr string
	switch u := GroupID.(type) {
	case int:
		GroupIDStr = strconv.Itoa(u)
	case int64:
		GroupIDStr = strconv.FormatInt(u, 10)
	case string:
		GroupIDStr = u
	default:
		// 可能需要处理其他类型或报错
		return ""
	}

	key := appID + "_" + GroupIDStr
	return GetMsgTypeByKey(key)
}
