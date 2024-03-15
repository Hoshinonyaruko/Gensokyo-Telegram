package images

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/hoshinonyaruko/gensokyo-telegram/config"
	"github.com/hoshinonyaruko/gensokyo-telegram/oss"
)

// 将base64图片通过lotus转换成url
func UploadBase64ImageToServer(base64Image string) (string, error) {
	extraPicAuditingType := config.GetOssType()

	// 根据不同的extraPicAuditingType值来调整函数行为
	switch extraPicAuditingType {
	case 0:
		// 原有的函数行为
		return originalUploadBehavior(base64Image)
	case 1:
		return oss.UploadAndAuditImage(base64Image) //腾讯
	case 2:
		return oss.UploadAndAuditImageB(base64Image) //百度
	case 3:
		return oss.UploadAndAuditImageA(base64Image) //阿里
	default:
		return "", errors.New("invalid extraPicAuditingType")
	}
}

func originalUploadBehavior(base64Image string) (string, error) {
	// 原有的UploadBase64ImageToServer函数的实现
	protocol := "http"
	serverPort := config.GetPortValue()
	if serverPort == "443" || serverPort == "8443" {
		protocol = "https"
	}

	if config.GetLotusValue() {
		serverDir := config.GetServer_dir()
		url := fmt.Sprintf("%s://%s:%s/uploadpic", protocol, serverDir, serverPort)

		resp, err := postImageToServer(base64Image, url)
		if err != nil {
			return "", err
		}
		return resp, nil
	}

	serverDir := config.GetServer_dir()
	if serverPort == "443" || serverPort == "8443" {
		protocol = "http"
		serverPort = "444"
	}

	if isPublicAddress(serverDir) {
		url := fmt.Sprintf("%s://127.0.0.1:%s/uploadpic", protocol, serverPort)

		resp, err := postImageToServer(base64Image, url)
		if err != nil {
			return "", err
		}
		return resp, nil
	}
	return "", errors.New("local server uses a private address; image upload failed")
}

// 将base64语音通过lotus转换成url
func UploadBase64RecordToServer(base64Image string) (string, error) {
	// 根据serverPort确定协议
	protocol := "http"
	serverPort := config.GetPortValue()
	if serverPort == "443" || serverPort == "8443" {
		protocol = "https"
	}

	if config.GetLotusValue() {
		serverDir := config.GetServer_dir()
		url := fmt.Sprintf("%s://%s:%s/uploadrecord", protocol, serverDir, serverPort)

		resp, err := postRecordToServer(base64Image, url)
		if err != nil {
			return "", err
		}
		return resp, nil
	}

	serverDir := config.GetServer_dir()
	// 当端口是443时，使用HTTP和444端口
	if serverPort == "443" || serverPort == "8443" {
		protocol = "http"
		serverPort = "444"
	}

	if isPublicAddress(serverDir) {
		url := fmt.Sprintf("%s://127.0.0.1:%s/uploadrecord", protocol, serverPort)

		resp, err := postRecordToServer(base64Image, url)
		if err != nil {
			return "", err
		}
		return resp, nil
	}
	return "", errors.New("local server uses a private address; image record failed")
}

// 请求图床api(图床就是lolus为false的gensokyo)
func postImageToServer(base64Image, targetURL string) (string, error) {
	data := url.Values{}
	data.Set("base64Image", base64Image) // 修改字段名以与服务器匹配

	resp, err := http.PostForm(targetURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error response from server: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	var responseMap map[string]interface{}
	if err := json.Unmarshal(body, &responseMap); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if value, ok := responseMap["url"]; ok {
		return fmt.Sprintf("%v", value), nil
	}

	return "", fmt.Errorf("URL not found in response")
}

// 请求语音床api(图床就是lolus为false的gensokyo)
func postRecordToServer(base64Image, targetURL string) (string, error) {
	data := url.Values{}
	data.Set("base64Record", base64Image) // 修改字段名以与服务器匹配

	resp, err := http.PostForm(targetURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error response from server: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	var responseMap map[string]interface{}
	if err := json.Unmarshal(body, &responseMap); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if value, ok := responseMap["url"]; ok {
		return fmt.Sprintf("%v", value), nil
	}

	return "", fmt.Errorf("URL not found in response")
}

// 判断是否公网ip 填写域名也会被认为是公网,但需要用户自己确保域名正确解析到gensokyo所在的ip地址
func isPublicAddress(addr string) bool {
	if strings.Contains(addr, "localhost") || strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "192.168.") {
		return false
	}
	if net.ParseIP(addr) != nil {
		return true
	}
	// If it's not a recognized IP address format, consider it a domain name (public).
	return true
}

// isBase64 判断字符串是否为base64编码
func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// isHTTPURL 判断字符串是否为http或https链接
func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// downloadFile 下载文件并保存到临时文件
func downloadFile(url string, filetype string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 创建临时文件
	tmpFile, err := ioutil.TempFile("", "download*."+filetype)
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// 将内容写入临时文件
	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

// saveBase64ToTempFile 保存base64字符串到临时文件
func saveBase64ToTempFile(base64Str string, filetype string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return "", err
	}

	tmpFile, err := ioutil.TempFile("", "base64*."+filetype)
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	_, err = tmpFile.Write(data)
	if err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

// ProcessInput 处理输入字符串，上传文件并返回MediaId
// func ProcessInput(input string, clt *core.Client, filetype string) (string, error) {
// 	var filepath string
// 	var err error

// 	if isHTTPURL(input) {
// 		filepath, err = downloadFile(input, filetype)
// 	} else if isBase64(input) {
// 		filepath, err = saveBase64ToTempFile(input, filetype)
// 	} else {
// 		return "", errors.New("input is neither a valid URL nor a base64 string")
// 	}

// 	if err != nil {
// 		return "", err
// 	}

// 	var info *media.MediaInfo
// 	if filetype == "mp3" {
// 		info, err = media.UploadVoice(clt, filepath)
// 		if err != nil {
// 			mylog.Printf("mp3 path:%v", filepath)
// 			return "", err
// 		}
// 	} else {
// 		info, err = media.UploadImage(clt, filepath)
// 		if err != nil {
// 			return "", err
// 		}
// 	}

// 	return info.MediaId, nil
// }
