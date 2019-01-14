package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	signatureDateFormat string = time.RFC1123
	TimeGeneratedFormat string = time.RFC3339
)

type LogTime time.Time

func (t LogTime)MarshalJSON() ([]byte, error) {
	stamp := fmt.Sprintf("\"%s\"", time.Time(t).Format(TimeGeneratedFormat))
	return []byte(stamp), nil
}

type LogItem struct {
	TimeGenerated LogTime `json:"TimeGenerated"`
}

type LogAnalytics struct {
	workspaceId string
	sharedKey []byte
	logName string
	url string
	queue chan interface{}
	waitGroup sync.WaitGroup
	httpClient *http.Client
}

func NewLogAnalytics(workspaceId string, sharedKey string, logName string) *LogAnalytics {
	key, err := base64.StdEncoding.DecodeString(sharedKey)
	if err != nil {
		return nil
	}
	logAnalytics := &LogAnalytics{
		logName: logName,
		sharedKey: key,
		workspaceId: workspaceId,
		url: "https://" + workspaceId + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
		queue: make(chan interface{}),
		httpClient: &http.Client{
			Timeout: time.Second * 60,
		},
	}

	go logAnalytics.worker()
	go logAnalytics.worker()

	return logAnalytics
}

func (this *LogAnalytics)worker() {
	this.waitGroup.Add(1)
	defer this.waitGroup.Done()

	for job := range this.queue {
		this.send(job)
	}
}

func (this *LogAnalytics)Add(item interface{}) {
	this.queue <- item
}

func (this *LogAnalytics)AddMulti(items []interface{}) {
	for _, i := range items {
		this.Add(i)
	}
}

func (this* LogAnalytics)Finalize() {
	log.Print(" [->] Waiting for remaining Log Analytics items...")
	close(this.queue)
	this.waitGroup.Wait()
	log.Print(" [->] All Log Analytics items are sent.")
}

func (this* LogAnalytics)send(item interface{}) {
	dateString := time.Now().UTC().Format(signatureDateFormat)
	dateString = strings.Replace(dateString, "UTC", "GMT", -1)
	body, err := json.Marshal(item)
	if err != nil {
		log.Print("[LogAnalytics]: Could not marshal input: ", err.Error())
		return
	}

	req, err := http.NewRequest("POST", this.url, bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Log-Type", this.logName)
	req.Header.Set("Authorization", this.generateAuthorization("POST", len(body), dateString))
	req.Header.Set("x-ms-date", dateString)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("time-generated-field", "TimeGenerated")

	if err != nil {
		log.Print("[LogAnalytics]: Could create http request: ", err.Error())
		return
	}

	resp, err := this.httpClient.Do(req)
	if err != nil {
		log.Print("[LogAnalytics]: Could create send http request: ", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		responseBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Print("[LogAnalytics]: Could insert log item and could not read response body: ", err.Error())
			return
		}
		log.Print("[LogAnalytics]: Could not insert log item (", strconv.Itoa(resp.StatusCode), "): ", string(responseBody))
		return
	}

	return
}

func (this* LogAnalytics)generateAuthorization(method string, bodyLength int, dateString string) string {
	stringToHash := method + "\n" + strconv.Itoa(bodyLength) + "\napplication/json\n" + "x-ms-date:" + dateString + "\n/api/logs"
	return "SharedKey " + this.workspaceId + ":" + this.buildSignature(stringToHash)
}

func (this *LogAnalytics)buildSignature(message string) string {
	h := hmac.New(sha256.New, []byte(this.sharedKey))
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

