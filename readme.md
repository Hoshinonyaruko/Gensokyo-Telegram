<p align="center">
  <a href="https://www.github.com/hoshinonyaruko/gensokyo-telegram">
    <img src="images/head.gif" width="200" height="200" alt="gensokyo">
  </a>
</p>

<div align="center">

# gensokyo

_✨ 基于 [OneBot](https://github.com/howmanybots/onebot/blob/master/README.md) Telegram机器人Onebot v11 Golang 原生实现 ✨_  


</div>

<p align="center">
  <a href="https://raw.githubusercontent.com/hoshinonyaruko/gensokyo-telegram/main/LICENSE">
    <img src="https://img.shields.io/github/license/hoshinonyaruko/gensokyo" alt="license">
  </a>
  <a href="https://github.com/hoshinonyaruko/gensokyo-telegram/releases">
    <img src="https://img.shields.io/github/v/release/hoshinonyaruko/gensokyo?color=blueviolet&include_prereleases" alt="release">
  </a>
  <a href="https://github.com/howmanybots/onebot/blob/master/README.md">
    <img src="https://img.shields.io/badge/OneBot-v11-blue?style=flat&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABABAMAAABYR2ztAAAAIVBMVEUAAAAAAAADAwMHBwceHh4UFBQNDQ0ZGRkoKCgvLy8iIiLWSdWYAAAAAXRSTlMAQObYZgAAAQVJREFUSMftlM0RgjAQhV+0ATYK6i1Xb+iMd0qgBEqgBEuwBOxU2QDKsjvojQPvkJ/ZL5sXkgWrFirK4MibYUdE3OR2nEpuKz1/q8CdNxNQgthZCXYVLjyoDQftaKuniHHWRnPh2GCUetR2/9HsMAXyUT4/3UHwtQT2AggSCGKeSAsFnxBIOuAggdh3AKTL7pDuCyABcMb0aQP7aM4AnAbc/wHwA5D2wDHTTe56gIIOUA/4YYV2e1sg713PXdZJAuncdZMAGkAukU9OAn40O849+0ornPwT93rphWF0mgAbauUrEOthlX8Zu7P5A6kZyKCJy75hhw1Mgr9RAUvX7A3csGqZegEdniCx30c3agAAAABJRU5ErkJggg==" alt="gensokyo">
  </a>
  <a href="https://github.com/hoshinonyaruko/gensokyo-telegram/actions">
    <img src="images/badge.svg" alt="action">
  </a>
  <a href="https://goreportcard.com/report/github.com/hoshinonyaruko/gensokyo-telegram">
  <img src="https://goreportcard.com/badge/github.com/hoshinonyaruko/gensokyo-telegram" alt="GoReportCard">
  </a>
</p>

<p align="center">
  <a href="https://github.com/howmanybots/onebot/blob/master/README.md">文档</a>
  ·
  <a href="https://github.com/hoshinonyaruko/gensokyo-telegram/releases">下载</a>
  ·
  <a href="https://github.com/hoshinonyaruko/gensokyo-telegram/releases">开始使用</a>
  ·
  <a href="https://github.com/hoshinonyaruko/gensokyo-telegram/blob/master/CONTRIBUTING.md">参与贡献</a>
</p>
<p align="center">
  <a href="https://gensokyo.bot">项目主页:gensokyo.bot</a>
</p>

## 底层
- [`go-telegram-bot-api`](https://github.com/go-telegram-bot-api/telegram-bot-api): 本项目底层基于有9年历史的telegram 老牌 Go sdk 稳定可靠.

## 兼容性
gensokyo兼容 [OneBot-v11](https://github.com/botuniverse/onebot-11) ，并在其基础上做了一些扩展，详情请看 OneBot 的文档。

可以多种方式连接tg并提供onebotv11反向ws标准api,

支持以下连接方式:

- [x] 纯http轮询 getmsg获取信息
- [x] 自备域名,自备ssl证书,webhook连接tg
- [x] 自备域名,框架生成自签名ssl证书,webhook连接tg
- [x] ngrok临时免费域名,ngrok提供证书,webhook连接tg

支持连接koishi,nonebot2,trss,zerobot,MiraiCQ,hoshino..

支持连接tata,派蒙,炸毛,早苗,yobot...

支持连接Mirai(Overflow)...

可以与支持onebotV11适配器的项目相连接使用.

实现插件开发和用户开发者无需重新开发,复用过往生态的插件和使用体验.

持续完善中.....交流群:196173384

交流tg频道: [早苗tg交流](https://t.me/+vby2QSVS5xVhNWE1)

欢迎测试,询问任何有关使用的问题,有问必答,有难必帮~

## 配置指南

Trss项目请配置array=true

测试所用服务器位于新加坡,尚未测试telegram服务器到国内服务器的连通性,若遇到问题可以进群咨询或欢迎提出issue~

下方的需配置 均为config.yml的配置项,配置项右侧有注释解释和格式例子

- [x] 纯http轮询 getmsg获取信息

需配置 botToken httpGetMsg=true getMsgTimeOut(秒)

- [x] 自备域名,自备ssl证书,webhook连接tg

需配置 botToken webHookPath server_dir(如果你的域名是baidu.com,那么server_dir就是baidu.com,不带协议头) port=443 crt key 为\双写的证书路径

- [x] 自备域名,框架生成自签名ssl证书,webhook连接tg

需配置 botToken webHookPath server_dir(如果你的域名是baidu.com,那么server_dir就是baidu.com,不带协议头) port=443 customcert=true

- [x] ngrok临时免费域名,ngrok提供证书,webhook连接tg

需配置 botToken useNgrok=true ngrokKey port=任意非443 8443端口!

## 发送速度慢怎么办

以下两个参数可能会决定回复速度,可根据自身测试结果进行调节

highway : true

将图片url直接上传到telegram 服务器带宽低情况比发图片url更快 请自行感受速度决定是否开启

sendDirectResponse : false

是否在webhook返回时直接发送信息(在不同服务器条件,速度或更快或更慢都有可能) 请自行感受速度决定是否开启

## 特别鸣谢

- [`mnixry/nonebot-plugin-gocqhttp`](https://github.com/mnixry/nonebot-plugin-gocqhttp/): 本项目采用了mnixry编写的前端,并实现了与它对应的,基于Telegram后端api.

### 接口

由于本项目是由gensokyo-qqapi转换迁移而来，目前已经支持nb2\yunzai\早苗\koishi等框架的图文收发，暂时仅支持反向ws方式连接Onebotv11机器人应用.

- [] HTTP API
- [] 反向 HTTP POST
- [] 正向 WebSocket
- [x] 反向 WebSocket

### 拓展支持

> 拓展 API 可前往 [文档](docs/cqhttp.md) 查看

- [x] 连接多个ws地址
- [x] 将Telegram用户信息虚拟成群事件/私聊事件
- [x] 持续更新~


### 实现

<details>
<summary>已实现 CQ 码</summary>

#### 符合 OneBot 标准的 CQ 码

| CQ 码        | 功能                        |
| ------------ | --------------------------- |
| [CQ:face]    | [QQ 表情]                   |
| [CQ:record]  | [语音]                      |
| [CQ:video]   | [短视频]                    |
| [CQ:at]      | [@某人]                     |
| [CQ:share]   | [链接分享]                  |
| [CQ:music]   | [音乐分享] [音乐自定义分享] |
| [CQ:reply]   | [回复]                      |
| [CQ:forward] | [合并转发]                  |
| [CQ:node]    | [合并转发节点]              |
| [CQ:xml]     | [XML 消息]                  |
| [CQ:json]    | [JSON 消息]                 |

todo,正在施工中

#### 拓展 CQ 码及与 OneBot 标准有略微差异的 CQ 码

| 拓展 CQ 码     | 功能                              |
| -------------- | --------------------------------- |
| [CQ:image]     | [图片]                            |
| [CQ:poke]      | [戳一戳]                          |
| [CQ:node]      | [合并转发消息节点]                |
| [CQ:markdown]  | [markdown卡片收发] |
| [CQ:tts]       | [文本转语音]                      |


</details>

<details>
<summary>已实现 API</summary>

#### 符合 OneBot 标准的 API

| API                      | 功能                   |
| ------------------------ | ---------------------- |
| /send_private_msg√        | [发送私聊消息]         |
| /send_group_msg√         | [发送群消息]           |
| /send_guild_channel_msg√ | [发送频道消息]         |
| /send_msg√               | [发送消息]             |
| /delete_msg              | [撤回信息]             |
| /set_group_kick          | [群组踢人]             |
| /set_group_ban√          | [群组单人禁言]         |
| /set_group_whole_ban√    | [群组全员禁言]         |
| /set_group_admin         | [群组设置管理员]       |
| /set_group_card          | [设置群名片（群备注）] |
| /set_group_name          | [设置群名]             |
| /set_group_leave         | [退出群组]             |
| /set_group_special_title | [设置群组专属头衔]     |
| /set_friend_add_request  | [处理加好友请求]       |
| /set_group_add_request   | [处理加群请求/邀请]    |
| /get_login_info√         | [获取登录号信息]       |
| /get_stranger_info       | [获取陌生人信息]       |
| /get_friend_list√        | [获取好友列表]         |
| /get_group_info√          | [获取群/频道信息]     |
| /get_group_list√         | [获取群列表]           |
| /get_group_member_info√  | [获取群成员信息]       |
| /get_group_member_list√  | [获取群成员列表]       |
| /get_group_honor_info    | [获取群荣誉信息]       |
| /can_send_image√         | [检查是否可以发送图片] |
| /can_send_record         | [检查是否可以发送语音] |
| /get_version_info√       | [获取版本信息]         |
| /set_restart√             | [重启 gensokyo]       |
| /.handle_quick_operation | [对事件执行快速操作]   |


#### 拓展 API 及与 OneBot 标准有略微差异的 API

| 拓展 API                    | 功能                   |
| --------------------------- | ---------------------- |
| /set_group_portrait         | [设置群头像]           |
| /get_image                  | [获取图片信息]         |
| /get_msg                    | [获取消息]             |
| /get_forward_msg            | [获取合并转发内容]     |
| /send_group_forward_msg√     | [发送合并转发(群)]     |
| /.get_word_slices           | [获取中文分词]         |
| /.ocr_image                 | [图片 OCR]             |
| /get_group_system_msg       | [获取群系统消息]       |
| /get_group_file_system_info | [获取群文件系统信息]   |
| /get_group_root_files       | [获取群根目录文件列表] |
| /get_group_files_by_folder  | [获取群子目录文件列表] |
| /get_group_file_url         | [获取群文件资源链接]   |
| /get_status√                 | [获取状态]             |


</details>

<details>
<summary>已实现 Event</summary>

#### 符合 OneBot 标准的 Event（部分 Event 比 OneBot 标准多上报几个字段，不影响使用）

| 事件类型 | Event            |
| -------- | ---------------- |
| 消息事件 | [私聊信息]√       |
| 消息事件 | [群消息]√         |
| 通知事件 | [群文件上传]     |
| 通知事件 | [群管理员变动]   |
| 通知事件 | [群成员减少]     |
| 通知事件 | [群成员增加]     |
| 通知事件 | [群禁言]         |
| 通知事件 | [好友添加]       |
| 通知事件 | [群消息撤回]     |
| 通知事件 | [好友消息撤回]   |
| 通知事件 | [群内戳一戳]     |
| 通知事件 | [群红包运气王]   |
| 通知事件 | [群成员荣誉变更] |
| 请求事件 | [加好友请求]     |
| 请求事件 | [加群请求/邀请]  |


#### 拓展 Event

| 事件类型 | 拓展 Event       |
| -------- | ---------------- |
| 通知事件 | [好友戳一戳]     |
| 通知事件 | [群内戳一戳]     |
| 通知事件 | [群成员名片更新] |
| 通知事件 | [接收到离线文件] |


</details>

## 关于 ISSUE

以下 ISSUE 会被直接关闭

- 提交 BUG 不使用 Template
- 询问已知问题
- 提问找不到重点
- 重复提问

> 请注意, 开发者并没有义务回复您的问题. 您应该具备基本的提问技巧。  
> 有关如何提问，请阅读[《提问的智慧》](https://github.com/ryanhanwu/How-To-Ask-Questions-The-Smart-Way/blob/main/README-zh_CN.md)

## 性能

10mb内存占用 端口错开可多开 稳定运行无报错