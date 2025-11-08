// Copyright 2025-present Fridolin Siegmund, Stefano Acquaviti
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ponalyzer/injector"
)

// Responds to requests to scan a PCAP file for OMCI messages.
// Processes an entire PCAP file and then serves all message-data.
func messagesHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Header().Set("Content-Type", "application/json")

	// Read/Decode file name from request
	var scanData filenameStruct
	err := json.NewDecoder(r.Body).Decode(&scanData)

	if err != nil {
		println("ERROR: http", err.Error())
		http.Error(w, "ERROR", http.StatusBadRequest)
		return
	}

	// Process and retrieve messages from PCAP file
	messages := packetsFromPCAP(scanData.Filename)

	// Serve/Send all message-data converted to JSON
	if messages != nil {
		messagesJson, _ := json.Marshal(messages)
		w.Write(messagesJson)
	} else {
		messages, _ := json.Marshal("")
		w.Write(messages)
	}

}

func fileListHandler(w http.ResponseWriter, r *http.Request) {
	// Set headers
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Header().Set("Content-Type", "application/json")

	type FileListJSON struct {
		FileList []string `json:"FileList"`
	}

	var file_list []string = nil

	err := filepath.WalkDir("pcaps/", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// fmt.Printf("%s\n", path)
		file_name := strings.TrimPrefix(path, "pcaps/")

		if file_name != "" {
			file_list = append(file_list, file_name)
		}

		return nil
	})
	if err != nil {
		fmt.Println("Error:", err)
	}

	var message FileListJSON
	message.FileList = file_list

	fmt.Println("message: ", message)

	messageJson, err := json.Marshal(message)
	if err != nil {
		println("ERROR: ", err.Error())
	}

	w.Write(messageJson)

}

// Responds to individual get-requests sent by client in interval decided by the client.
// Serves all messages currently stored on messageChannel whenever a request arrives
func liveHandler(w http.ResponseWriter, r *http.Request) {

	// Set headers
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Header().Set("Content-Type", "application/json")

	var messages []omciMessageStruct = nil

	// Append all messages inside messageChannel to buffer
	for len(messageChannel) > 0 {
		messages = append(messages, <-messageChannel)
	}

	// Send/Serve messages to the client
	if messages == nil {
		messages, _ := json.Marshal("")
		w.Write(messages)
	} else {
		messagesJson, _ := json.Marshal(messages)
		w.Write(messagesJson)
	}
}

// Handle start-message to start sniffer and open channels
func startHandler(w http.ResponseWriter, r *http.Request) {

	// Set headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/plain")

	if !startSniffer() {
		w.Write([]byte("Failed to start sniffer!"))
		return
	}

	w.Write([]byte("Sniffer started!"))
}

// Handle stop-message to stop sniffer and close channels
func stopHandler(w http.ResponseWriter, r *http.Request) {

	// Set headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/plain")

	stopSniffer()

	w.Write([]byte("Sniffer stopped!"))
}

/*
Establishes and serves OMCI message data over a Server-Sent-Event (SSE) connection to a client

Relevant config Parameters:
counterLimit = config["maxPackets"] sets upper threshold of number of messages to be processed before being sent to the client.
timeLimit = config["interval"] sets interval/timelimit at which to send all currently processed and buffered messages.
*/
func sseHandler(w http.ResponseWriter, r *http.Request) {

	// Set SSE connection headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Cache-Control", "no-cache")

	var messages []omciMessageStruct = nil
	messageCounter := 0

	// Read packet limit from config or apply default
	counterLimit, err := strconv.Atoi(config["maxPackets"])

	if err != nil {
		println("ERROR: ", err.Error())
		counterLimit = 100
	}

	// Read time limit from config or apply default
	timeLimit, err := strconv.Atoi(config["interval"])

	if err != nil {
		println("ERROR: ", err.Error())
		timeLimit = 1000
	}

	// No time limit needs special rule because it cannot be <= 0
	noTimeLimit := false

	if timeLimit <= 0 {
		timeLimit = 10000
		noTimeLimit = true
	}

	// Set ticker according to time limit
	interval := time.NewTicker(time.Duration(timeLimit) * time.Millisecond)
	defer interval.Stop()
	flushedAt := time.Now()

	// Main loop for reading messages from messageChannel and serving them to the client whenever time- or packet-limit is reached
	// Blocking until either enough messages or time limit is reached
	// Messages are sent in json format for SSE events
	// Messages on messageChannel are already in json format
	for {
		select {
		// Case if time limit is reached and ticker sends a signal to serve messages to the client
		case <-interval.C:
			if !noTimeLimit && time.Since(flushedAt) >= time.Duration(timeLimit)*time.Millisecond && messages != nil {
				messagesJson, _ := json.Marshal(messages)
				w.Write([]byte("data: " + string(messagesJson) + "\n\n"))
				w.(http.Flusher).Flush()
				messages = nil
				messageCounter = 0
				flushedAt = time.Now()
			}

		// Case if time limit is not reached and a message is available on messageChannel
		case message, ok := <-messageChannel:
			// If !ok channel is closed (sniffer stopped) and all messages remaining in buffer are to be sent to the client
			if !ok {
				println("Channel Closed!")
				if messages != nil {
					messagesJson, _ := json.Marshal(messages)
					w.Write([]byte("data: " + string(messagesJson) + "\n\n"))
					w.(http.Flusher).Flush()
					messages = nil
					messageCounter = 0
				}
				// Also send message to close SSE connection
				w.Write([]byte("event: close\ndata:close\n\n"))
				w.(http.Flusher).Flush()
				return
			}

			// Append single message to buffered messages and increase counter
			messages = append(messages, message)
			messageCounter++

			// If packet limit is reached, sent messages to the client
			if counterLimit > 0 && messageCounter >= counterLimit {
				messagesJson, _ := json.Marshal(messages)
				w.Write([]byte("data: " + string(messagesJson) + "\n\n"))
				w.(http.Flusher).Flush()
				messages = nil
				messageCounter = 0
				flushedAt = time.Now()
			}
		}
	}
}

// Serves Index landing page, stops scans, clears buffers and channels, reloads config
func indexHandler(w http.ResponseWriter, r *http.Request) {

	stopSniffer()

	//config = readConfig()

	omciPacketsBuffer = nil

	resetStats()

	http.ServeFile(w, r, "client.html")
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {

	http.Redirect(w, r, "/index/", http.StatusMovedPermanently)
}

// Config struct containing config-data received from client
type configStruct struct {
	Iface    string `json:"Iface"`
	Filter   string `json:"Filter"`
	Packets  string `json:"Packets"`
	Interval string `json:"Interval"`
	Buffer   string `json:"Buffer"`
}

// Receives and applies config parameters sent from client
func configHandler(w http.ResponseWriter, r *http.Request) {

	// Set headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/plain")

	// Read/Decode config from request
	var configData configStruct
	err := json.NewDecoder(r.Body).Decode(&configData)

	if err != nil {
		println("ERROR: ", err.Error())
		http.Error(w, "ERROR", http.StatusBadRequest)
		return
	}

	config["interface"] = configData.Iface
	config["filter"] = configData.Filter
	config["maxPackets"] = configData.Packets
	config["interval"] = configData.Interval
	config["buffer"] = configData.Buffer

	w.Write([]byte("Config Applied!"))
}

type filenameStruct struct {
	Filename string `json:"Filename"`
}

// Handles export requests and writes omci packets to a pcap file
func exportHandler(w http.ResponseWriter, r *http.Request) {

	// Set headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/plain")

	// Read/Decode file name from request
	var exportData filenameStruct
	err := json.NewDecoder(r.Body).Decode(&exportData)

	if err != nil {
		println("ERROR: http", err.Error())
		http.Error(w, "ERROR", http.StatusBadRequest)
		return
	}

	// Write to pcap file
	written, filename := packetsToPCAP(exportData.Filename)

	if written == 0 {
		w.Write([]byte("No packets to write!"))
		return
	}

	w.Write([]byte("Export successful!\n" + strconv.Itoa(written) + " packets written to " + filename))
}

// Injection struct containing information about an attempted injection
type injectionStruct struct {
	Type       string `json:"Type"`
	IP         string `json:"IP"`
	Timeout    string `json:"Timeout"`
	Port       string `json:"Port"`
	Onu        string `json:"Onu"`
	Tid        string `json:"Tid"`
	Instance   string `json:"Instance"`
	Class      string `json:"Class"`
	Commands   string `json:"Commands"`
	Attributes string `json:"Attributes"`
	Message    string `json:"Message"`
}

// Handles injection requests and serves result
func injectionHandler(w http.ResponseWriter, r *http.Request) {

	// Set headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/plain")

	// Read injection parameters from request
	var injectionData injectionStruct
	err := json.NewDecoder(r.Body).Decode(&injectionData)

	if err != nil {
		println("ERROR: ", err.Error())
		http.Error(w, "ERROR", http.StatusBadRequest)
		return
	}

	// Convert parameters
	timeout, _ := strconv.Atoi(injectionData.Timeout)
	port, _ := strconv.Atoi(injectionData.Port)
	onu, _ := strconv.Atoi(injectionData.Onu)
	tid, _ := strconv.Atoi(injectionData.Tid)
	instance, _ := strconv.Atoi(injectionData.Instance)
	class, _ := strconv.Atoi(injectionData.Class)
	commands, _ := strconv.Atoi(injectionData.Commands)

	// Call injection module function
	result := injector.InjectMessage(injectionData.IP, timeout, injectionData.Type, uint32(port), uint32(onu), uint16(tid), uint16(instance), uint16(class), commands, injectionData.Attributes, injectionData.Message)

	w.Write([]byte(result))
}

// Global config map
//
// Possible parameters: interface, filter, maxPackets, interval
var config map[string]string

// Reads config and launches webserver http handlers
func main() {

	config = readConfig()

	// Handle different requests from clients
	http.HandleFunc("/messages/pcap", messagesHandler)

	http.HandleFunc("/messages/showfiles", fileListHandler)

	http.HandleFunc("/messages/live", liveHandler)

	http.HandleFunc("/messages/start", startHandler)

	http.HandleFunc("/messages/stop", stopHandler)

	http.HandleFunc("/messages/sse", sseHandler)

	http.HandleFunc("/messages/config", configHandler)

	http.HandleFunc("/messages/export", exportHandler)

	http.HandleFunc("/messages/inject", injectionHandler)

	http.HandleFunc("/index/", indexHandler)

	http.HandleFunc("/", redirectHandler)

	// Provide JS and Bootstrap dependencies to clients
	http.Handle("/index/script.js", http.StripPrefix("/index/", http.FileServer(http.Dir("./"))))
	//http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("js"))))

	http.Handle("/index/bootstrap/css/bootstrap.min.css", http.StripPrefix("/index/", http.FileServer(http.Dir("./"))))

	http.Handle("/index/bootstrap/js/bootstrap.bundle.min.js", http.StripPrefix("/index/", http.FileServer(http.Dir("./"))))

	http.Handle("/index/bootstrap/css/bootstrap.min.css.map", http.StripPrefix("/index/", http.FileServer(http.Dir("./"))))

	http.Handle("/index/bootstrap/js/bootstrap.bundle.min.js.map", http.StripPrefix("/index/", http.FileServer(http.Dir("./"))))

	// Start listening
	println("Serving at port 8080 ...")
	log.Fatal(http.ListenAndServe(":8080", nil))

}

/*
Read config from a config.csv file provided in format:

interface,"ens18"
filter,"tcp && port 9191"
maxPackets,100
interval,1000
buffer,10000
*/
func readConfig() map[string]string {
	configFile, err := os.Open("config.csv")

	if err != nil {
		println("ERROR: ", err.Error())
		return nil
	}

	configReader := csv.NewReader(configFile)

	configLines, err := configReader.ReadAll()

	if err != nil {
		println("ERROR: ", err.Error())
		return nil
	}

	configFile.Close()

	configMap := make(map[string]string)

	println("Loading config:")
	for _, entry := range configLines {
		configMap[entry[0]] = entry[1]
		println(entry[0] + ": " + entry[1])
	}

	return configMap
}
