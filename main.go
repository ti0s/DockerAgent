package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	_ "github.com/tim1020/godaemon"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"io"
	log "unknwon.dev/clog/v2"
)
var token string
var port int
var verSion = "1.1"
type sliceFlag []string
func (f *sliceFlag) String() string {
	return fmt.Sprintf("%v", []string(*f))
}
func (f *sliceFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}
func init() {
	_ = log.NewConsole()
	gin.DisableConsoleColor()

	f, _ := os.Create("agent.log")
	gin.DefaultWriter = io.MultiWriter(f)
	gin.SetMode(gin.ReleaseMode)
}

type dockername struct {
	DockerName string
}

type rmatcontainer struct {
	Id int
}
type atcontainer struct {
	Time string
	DockerName string
}

type imagesname struct {
	ImagesName string
}
type pushflag struct {
	DockerName string
	Flag string
}
type runcontainer struct {
	ImagesName string
	DockerName string
	PortIn int
	PortOut int
	Privilege bool
	HostName string
}
func main() {
	var Whitelist sliceFlag
	flag.StringVar(&token, "token", randomString(32), "X-Auth-Token")
	flag.IntVar(&port, "port", 65123, "HTTP Listening Port")
	flag.Var(&Whitelist, "host", "Allow IP address access,Ps: -host=172.30.0.1 -host=172.30.0.2")

	flag.Parse()
	localHost := []string{"127.0.0.1"}
	Whitelist = append(Whitelist, localHost...)

	var checkDockerCommand = Cmd("docker")
	if find := strings.Contains(checkDockerCommand, "command not found"); find {
		fmt.Print("Docker Application Doesn't Exist Please Install This Program.")
		return
	}
	var checkAtCommand = Cmd("at")
	if find := strings.Contains(checkAtCommand, "command not found"); find {
		fmt.Print("At Application Doesn't Exist Please Install This Program.")
		return
	}
	log.Info("Docker Manage Agent. Version: %s ", verSion)
	log.Info("Listening and serving HTTP on:0.0.0.0:%s ", strconv.Itoa(port))
	log.Info("X-Auth-Token: %s", token)
	log.Info("Allow IP address access: %v", Whitelist)
	r := gin.Default()
	auth := r.Use(func(c *gin.Context) {
		whitelisted := false
		for _, v := range Whitelist {
			if v == c.ClientIP() {
				whitelisted = true
			}
		}
		if whitelisted != true {
			c.JSON(makeJSON(401, 401, "The IP Address Unauthorized!"))
			c.Abort()
			return
		}
		if c.GetHeader("X-Auth-Token") != token {
			c.JSON(makeJSON(401, 401, "Please Authorized Token!"))
			c.Abort()
			return
		}
		c.Next()
	})
	// 尝试互通
	auth.POST("/ping", pong)
	auth.POST("/info", info)
	auth.POST("/version", version)
	auth.POST("/images", images)
	auth.POST("/container", container)
	auth.POST("/rmContainer", rmContainer)
	auth.POST("/pushFlag", pushFlag)
	auth.POST("/atContainer", atContainer)
	auth.POST("/runContainer", runContainer)
	auth.POST("/inspectImages", inspectImages)
	auth.POST("/rmAtContainer", rmAtContainer)

	// 路由不存在
	r.NoRoute(func(c *gin.Context) {
		c.JSON(makeJSON(404, 404, "404 Not Found!"))
		c.Abort()
		return
	})

	r.Run(":"+strconv.Itoa(port))
}
func runContainer(c *gin.Context){
	if checkRun() == false{
		c.JSON(makeJSON(404, 404, "Docker Is Not Running!"))
		c.Abort()
		return
	}else{
		var runContainer runcontainer
		if err := c.BindJSON(&runContainer); err != nil {
			c.JSON(makeJSON(400, 400, "Data Error!"))
			return
		}
		if runContainer.HostName==""{
			runContainer.HostName = "VINCTF"
		}
		if runContainer.DockerName==""{
			runContainer.DockerName = randomString(32)
		}
		if runContainer.ImagesName==""{
			c.JSON(makeJSON(404, 404, "Docker Images Not Found!"))
			c.Abort()
			return
		}
		var imagesExist = Cmd("docker images | grep "+runContainer.ImagesName+"| wc -l")
		re, _ := regexp.Compile(" +")
		imagesExist = re.ReplaceAllLiteralString(imagesExist, "")
		line := strings.Trim(imagesExist, "\n ")
		int,_:=strconv.Atoi(line)
		if int==0{
			c.JSON(makeJSON(404, 404, "Docker Images Not Found!"))
			c.Abort()
			return
		}
		if runContainer.PortIn<1 || runContainer.PortIn>65535{
			c.JSON(makeJSON(404, 404, "Docker Port Does Not Exist!"))
			c.Abort()
			return
		}
		if runContainer.PortOut<1 || runContainer.PortOut>65535{
			c.JSON(makeJSON(404, 404, "Docker Port Does Not Exist!"))
			c.Abort()
			return
		}
		if runContainer.Privilege==false {
			Command := "docker run -tid -p "+strconv.Itoa(runContainer.PortOut)+":"+strconv.Itoa(runContainer.PortIn)+" --name="+runContainer.DockerName+" --hostname="+runContainer.HostName+" "+runContainer.ImagesName
			var cmd = Cmd(Command)
			line := strings.Trim(cmd, "\n ")
			c.JSON(successJSON(line))
		}else{
			Command := "docker run -tid -p "+strconv.Itoa(runContainer.PortOut)+":"+strconv.Itoa(runContainer.PortIn)+" --name="+runContainer.DockerName+" --privileged=true --hostname="+runContainer.HostName+" "+runContainer.ImagesName
			var cmd = Cmd(Command)
			line := strings.Trim(cmd, "\n ")
			c.JSON(successJSON(line))
		}
		return
	}
}
func pushFlag(c *gin.Context) {
	if checkRun() == false{
		c.JSON(makeJSON(404, 404, "Docker Is Not Running!"))
		c.Abort()
		return
	}else{
		var pushFlag pushflag
		if err := c.BindJSON(&pushFlag); err != nil {
			c.JSON(makeJSON(400, 400, "Data Error!"))
			return
		}
		var cmd = Cmd("docker exec -i "+pushFlag.DockerName+" /bin/sh /flag.sh '"+pushFlag.Flag+"'")
		if cmd == ""{
			c.JSON(successJSON("SUCCESS"))
		}else{
			c.JSON(makeJSON(400, 400, "Push Flag Error!"))
		}
		return
	}
}
func rmContainer(c *gin.Context) {
	if checkRun() == false{
		c.JSON(makeJSON(404, 404, "Docker Is Not Running!"))
		c.Abort()
		return
	}else{
		var dockerName dockername
		if err := c.BindJSON(&dockerName); err != nil {
			c.JSON(makeJSON(400, 400, "Data Error!"))
			return
		}
		var cmd = Cmd("docker rm -f "+dockerName.DockerName)
		c.JSON(successJSON(cmd))
		return
	}
}
func atContainer(c *gin.Context){
	if checkRun() == false{
		c.JSON(makeJSON(404, 404, "Docker Is Not Running!"))
		c.Abort()
		return
	}else{
		var atContainer atcontainer
		if err := c.BindJSON(&atContainer); err != nil {
			c.JSON(makeJSON(400, 400, "Data Error!"))
			return
		}
		if atContainer.Time==""{
			var t = int32(time.Now().Unix())+3600
			timestamp := int64(t)
			Loc, _ := time.LoadLocation("Asia/Shanghai")
			t3 := time.Unix(timestamp, 0).In(Loc)
			timeFormat := "15:04"
			atContainer.Time = t3.Format(timeFormat)
		}
		if atContainer.DockerName==""{
			c.JSON(makeJSON(404, 404, "Docker Container Not Found!"))
			c.Abort()
			return
		}
		var containerExist = Cmd("docker ps -a | grep "+atContainer.DockerName+" | wc -l")
		re, _ := regexp.Compile(" +")
		containerExist = re.ReplaceAllLiteralString(containerExist, "")
		line := strings.Trim(containerExist, "\n ")
		int,_:=strconv.Atoi(line)
		if int==0{
			c.JSON(makeJSON(404, 404, "Docker Container Not Found!"))
			c.Abort()
			return
		}
		var fileName = "/tmp/"+randomString(32)
		f, err := os.Create(fileName)
		defer f.Close()
		if err == nil {
			var content = "#!/bin/sh\ndocker rm -f "+atContainer.DockerName
			_, err = f.Write([]byte(content))
			if err != nil {
				c.JSON(makeJSON(404, 404, "The Permission Is Insufficient."))
				c.Abort()
				return
			}
		
		}
		//Cmd("script -c 'at -f /tmp/0hjQ4hOAvfYseloDzvINE9CdKbHOD15O 12:00' -q /dev/null")
		var pushAt = Cmd("script -c 'at -f "+fileName+" "+atContainer.Time+"' -q /dev/null")
		//fmt.Print("script -c 'at -f "+fileName+" "+atContainer.Time+"' -q /dev/null")
		os.Remove(fileName)
		
		if find := strings.Contains(pushAt, "job"); find {
			lines := strings.Split(strings.Trim(pushAt, "\n "), " ")
			c.JSON(successJSON(lines[1]))
			return
		}else{
			c.JSON(makeJSON(404, 404, "Failed To Create A Scheduled Task."))
			c.Abort()
			return
		}
	}
}
func rmAtContainer(c *gin.Context){
	var rmAtContainer rmatcontainer
	if err := c.BindJSON(&rmAtContainer); err != nil {
		c.JSON(makeJSON(400, 400, "Data Error!"))
		return
	}
	Cmd("atrm "+strconv.Itoa(rmAtContainer.Id))
	c.JSON(successJSON("SUCCESS"))
	c.Abort()
	return
}
func inspectImages(c *gin.Context) {
	if checkRun() == false{
		c.JSON(makeJSON(404, 404, "Docker Is Not Running!"))
		c.Abort()
		return
	}else{
		var imagesName imagesname
		if err := c.BindJSON(&imagesName); err != nil {
			c.JSON(makeJSON(400, 400, "Data Error!"))
			return
		}
		var imagesInspect = Cmd("docker inspect "+imagesName.ImagesName)
		re, _ := regexp.Compile(" +")
		re1, _ := regexp.Compile("\\n+")
		imagesInspect = re.ReplaceAllLiteralString(imagesInspect, "")
		imagesInspect = re1.ReplaceAllLiteralString(imagesInspect, "")
		imagesInspect = base64.StdEncoding.EncodeToString([]byte(imagesInspect))
		c.JSON(successJSON(imagesInspect))
		return
	}
}
func pong(c *gin.Context) {
	if checkRun() == false{
		c.JSON(makeJSON(404, 404, "Docker Is Not Running!"))
		c.Abort()
		return
	}else{
		c.JSON(makeJSON(200, 200, "PONG"))
		c.Abort()
		return
	}
}
func checkRun() bool{
	_, err := os.Stat("/bin/docker")
	if os.IsNotExist(err) {
		return false
	}
	var cmd = Cmd("docker info")
	if find := strings.Contains(cmd, "Is the docker daemon running"); find {
		return false
	}
	return true
}
func images(c *gin.Context) {
	if checkRun() == false{
		c.JSON(makeJSON(404, 404, "Docker Is Not Running!"))
		c.Abort()
		return
	}else{
		var cmd = Cmd("docker images | tail -n +2")
		re, _ := regexp.Compile(" +")
		cmd = re.ReplaceAllLiteralString(cmd, ",")
		cmd = strings.Replace(cmd, " ", ",", -1)
		lines := strings.Split(strings.Trim(cmd, "\n "), "\n")
		imagesList,_ := json.Marshal(lines)
		c.JSON(successJSON(imagesList))
		return
	}
}
func container(c *gin.Context) {
	if checkRun() == false{
		c.JSON(makeJSON(404, 404, "Docker Is Not Running!"))
		c.Abort()
		return
	}else{
		var cmd = Cmd("docker ps -a| tail -n +2")
		re, _ := regexp.Compile(" +")
		cmd = re.ReplaceAllLiteralString(cmd, ",")
		cmd = strings.Replace(cmd, " ", ",", -1)
		lines := strings.Split(strings.Trim(cmd, "\n "), "\n")
		containerList,_ := json.Marshal(lines)
		c.JSON(successJSON(containerList))
		return
	}
}
func info(c *gin.Context) {
	if checkRun() == false{
		c.JSON(makeJSON(404, 404, "Docker Is Not Running!"))
		c.Abort()
		return
	}else{
		var cmd = Cmd("docker info")
		re, _ := regexp.Compile(" +")
		cmd = re.ReplaceAllLiteralString(cmd, "")
		lines := strings.Split(strings.Trim(cmd, "\n "), "\n")
		imagesList,_ := json.Marshal(lines)
		c.JSON(successJSON(imagesList))
		return
	}
}
func version(c *gin.Context) {
	if checkRun() == false{
		c.JSON(makeJSON(404, 404, "Docker Is Not Running!"))
		c.Abort()
		return
	}else{
		var cmd = Cmd("docker version")
		re, _ := regexp.Compile(" +")
		cmd = re.ReplaceAllLiteralString(cmd, "")
		lines := strings.Split(strings.Trim(cmd, "\n "), "\n")
		imagesList,_ := json.Marshal(lines)
		c.JSON(successJSON(imagesList))
		return
	}
}
func makeJSON(httpStatusCode int, errCode int, msg interface{}) (int, interface{}) {
	return httpStatusCode, gin.H{"code": errCode, "msg": fmt.Sprint(msg)}
}
func successJSON(data interface{}) (int, interface{}) {
	return 200, gin.H{"code": 200, "data": data}
}
func Cmd(command string) string {
	cmd := exec.Command("/bin/bash","-c",command)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return err.Error()+": "+stderr.String()
	}
	result := out.String()
	return result
}
func randomString(n int) string {
	letterRunes := []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var bb bytes.Buffer
	bb.Grow(n)
	l := uint32(len(letterRunes))
	for i := 0; i < n; i++ {
		bb.WriteRune(letterRunes[binary.BigEndian.Uint32(getBytes(4))%l])
	}
	return bb.String()
}
func getBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}
