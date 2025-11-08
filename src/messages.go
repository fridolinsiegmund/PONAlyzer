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
	"encoding/hex"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	gp "github.com/google/gopacket"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/opencord/omci-lib-go/v2"
	"github.com/opencord/omci-lib-go/v2/generated"
	"golang.org/x/exp/utf8string"
)

// Counters
var seenPackets int = 0
var totalPackets int = 0

// Extract and decode OMCI-Messages from PCAP file.
// And potentially convert them into JSON string
func packetsFromPCAP(pcapFileName string) []omciMessageStruct {

	if pcapFileName == "" {
		pcapFileName = "testfile.pcap"
	}

	// If no .pcap suffix, append .pcap and try opening
	if !strings.HasSuffix(pcapFileName, ".pcap") {
		pcapFileName += ".pcap"
	}

	// Open PCAP-file
	pcapFile, err := pcap.OpenOffline("pcaps/" + pcapFileName)

	// Main buffer containing all OMCI-message information as appended (JSON) strings
	var messagesList []omciMessageStruct = nil

	if err != nil {
		println("ERROR: ", err.Error())
		return nil
	}

	defer pcapFile.Close()

	// Read BPF filter from config
	filter := config["filter"]

	// Or apply default filter
	if filter == "" {
		filter = "tcp && port 9191"
	}

	// Attempt setting BPF filter
	err = pcapFile.SetBPFFilter(filter)

	if err != nil {
		println("ERROR: ", err.Error())
		return nil
	}

	// Create channel containing packets read from PCAP-file
	packets := gopacket.NewPacketSource(pcapFile, pcapFile.LinkType()).Packets()
	linkType = pcapFile.LinkType()

	// Read buffer size from config
	bufferSize, err = strconv.Atoi(config["buffer"])

	// Or apply default
	if err != nil {
		println("ERROR: ", err.Error())
		bufferSize = 10000
	}

	if bufferSize <= 1 {
		bufferSize = 10000
	}

	// Check if pcap file is not evaluation mode
	// This is the actual branch used in practice
	if !strings.HasSuffix(pcapFileName, "perfeval.pcap") {
		// Iterate over and process all packets on packets channel
		for packet := range packets {

			message := processPacket(packet)

			// If Valid OMCI-message (message != nil), append to result and write into buffer
			if message != nil {
				bufferOMCIPacket(omciPacketStruct{packet: packet, omciMessages: message})
				// Append results to main buffer
				messagesList = append(messagesList, message...)

			}

			totalPackets++
		}
	} else {
		// If pcapFileName is "perfeval.pcap", start evaluation mode
		// and read fixed number of messages according to buffer size
		startTime := time.Now()

		// Read fixed number of messages
		for len(messagesList) < bufferSize {
			// Open PCAP-file
			pcapFile, _ := pcap.OpenOffline("pcaps/" + pcapFileName)
			// Attempt setting BPF filter
			pcapFile.SetBPFFilter(filter)
			// Create channel containing packets read from PCAP-file
			packets := gopacket.NewPacketSource(pcapFile, pcapFile.LinkType()).Packets()

			// Iterate over and process all packets on packets channel
			for packet := range packets {

				message := processPacket(packet)

				// If Valid OMCI-message (message != nil), append to result and write into buffer
				if message != nil {
					bufferOMCIPacket(omciPacketStruct{packet: packet, omciMessages: message})
					// Append results to main buffer
					messagesList = append(messagesList, message...)

				}

				totalPackets++
				if len(messagesList) >= bufferSize {
					break
				}
			}
			pcapFile.Close()
		}
		println("Processed packets:", time.Since(startTime).Milliseconds(), "ms")
	}

	printStats()

	return messagesList
}

// Declare global variables required for sniffing live network
var networkInterface *pcap.Handle
var networkPackets chan gopacket.Packet
var messageChannel chan omciMessageStruct
var omciPacketsBuffer []omciPacketStruct
var bufferSize int = 10000
var linkType layers.LinkType

// Start sniffing process using certain configuration parameters from global configuration map
func startSniffer() bool {

	var err error

	// Read network interface name from config
	interfaceName := config["interface"]

	// Or apply default interface name
	if interfaceName == "" {
		interfaceName = "ens18"
	}

	// Attempt opening network interface in promiscuous mode
	networkInterface, err = pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)

	if err != nil {
		println("ERROR: ", err.Error())
		return false
	}

	// Read BPF filter from config
	filter := config["filter"]

	// Or apply default filter
	if filter == "" {
		filter = "tcp && port 9191"
	}

	// Attempt setting BPF filter
	err = networkInterface.SetBPFFilter(filter)

	if err != nil {
		println("ERROR: ", err.Error())
		return false
	}

	// Create channel containing packets read from network interface
	networkPackets = gopacket.NewPacketSource(networkInterface, networkInterface.LinkType()).Packets()
	linkType = networkInterface.LinkType()

	// Read buffer size from config
	bufferSize, err = strconv.Atoi(config["buffer"])

	// Or apply default
	if err != nil {
		println("ERROR: ", err.Error())
		bufferSize = 10000
	}

	if bufferSize <= 1 {
		bufferSize = 10000
	}

	// Initialize messageChannel containing processed message information
	messageChannel = make(chan omciMessageStruct, bufferSize)

	// Start parallel process reading and processing packets from network interface
	go parallelPacketsFromNetwork()

	return true
}

// Stop sniffing process and close network interface and messageChannel channels
func stopSniffer() {
	if networkInterface != nil {
		networkInterface.Close()
	}

	if messageChannel != nil {
		close(messageChannel)
		messageChannel = nil
	}
}

// Parallel function to process packets from network interface
func parallelPacketsFromNetwork() {

	// As long as the networkPackets channel is open, wait for (blocking), read, and process packets
	for packet := range networkPackets {

		// Process packet
		message := processPacket(packet)

		// If Valid OMCI-message (message != nil), write OMCI-message information to messageChannel
		if message != nil {
			bufferOMCIPacket(omciPacketStruct{packet: packet, omciMessages: message})
			for _, m := range message {
				messageChannel <- m
			}
		}

		totalPackets++
	}

	printStats()
}

// Global counters
var totalDecodingErrors int = 0
var totalOmciMessages int = 0

// OMCI-message struct containing all information about an OMCI-message to be sent to a client
type omciMessageStruct struct {
	MessageNumber int       `json:"MessageNumber"`
	Messagetype   string    `json:"Messagetype"`
	TransactionId uint16    `json:"TransactionId"`
	InterfaceId   string    `json:"InterfaceId"`
	OnuId         string    `json:"OnuId"`
	Timestamp     time.Time `json:"Timestamp"`
	Source        string    `json:"Source"`
	Destination   string    `json:"Destination"`

	EntityClass  string         `json:"EntityClass"`
	InstanceId   uint16         `json:"InstanceId"`
	MessageLayer any            `json:"MessageLayer"`
	MessageData  map[string]any `json:"MessageData"`
	//Alarmtype    string         `json:"Alarmtype,omitempty"`
}

// Process an individual network packet by
// filtering relevant packets,
// finding potential OMCI-message if present,
// letting OMCI-decoder decode OMCI-message,
// converting OMCI-message information to JSON if desired.
func processPacket(packet gopacket.Packet) []omciMessageStruct {
	// Decode TCP-layer from packet
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	// Check that packet is TCP
	if tcpLayer != nil {

		packetTCP := tcpLayer.(*layers.TCP)

		// Extract TCP payload
		payload := packetTCP.Payload

		// Check for absolute minimal length to further filter out some packets
		if len(payload) >= 60 {

			seenPackets++

			// Payload as string
			var payloadString string = string(payload)
			// Contains all indices which potentially indicate an OMCI-message
			var omciIndex []int
			// Buffer containing OMCI-message information
			var messagesList []omciMessageStruct = nil

			// OMCI-Messages end with "00000028" + 4 bytes/8 hex-values checksum
			// OMCI-Messages are contained within the packets inconsistently
			// Case 1: Request packet contains bytes representing the messagebytes as a string excluding checksum (44 bytes/88 hex-values total)
			// Converting bytes into a string will return the bytes of the actual message (as a string)
			//omciIndex = strings.Index(payloadString, "00000028")

			// Find all potential OMCI-Message indices
			omciIndex = findOMCIMessageIndices(payloadString)

			// Check every index for OMCI-message
			for _, index := range omciIndex {
				// Message has to be at least 91 long in this format to be valid
				if index >= 91 {
					// Extract OMCI-message string
					omciString := payloadString[index-80 : index+8]
					// Check if selection is all ASCII (OMCI-messages contain only ASCII)
					if utf8string.NewString(omciString).IsASCII() {
						// Decode actual OMCI-message
						message := decodeOMCIMessage(omciString)
						if message != nil {
							// Extract interfaceId(portnumber) and onuId in front of OMCI-message
							message.InterfaceId, _ = strings.CutPrefix(hex.EncodeToString([]byte{payloadString[index-91]}), "0")
							message.OnuId, _ = strings.CutPrefix(hex.EncodeToString([]byte{payloadString[index-86]}), "0")
							// Add timestamp
							message.Timestamp = packet.Metadata().Timestamp.Local()
							message.Source = packet.NetworkLayer().NetworkFlow().Src().String() + ":" + strings.Split(packetTCP.SrcPort.String(), "(")[0]
							message.Destination = packet.NetworkLayer().NetworkFlow().Dst().String() + ":" + strings.Split(packetTCP.DstPort.String(), "(")[0]
							// Store message in buffer
							messagesList = append(messagesList, *message)
						}
					}
				}
			}

			// Case 2: Response packet contains message as bytes including checksum (48 bytes total)
			payloadString = hex.EncodeToString(payload)

			// Find all potential OMCI-Message indices
			omciIndex = findOMCIMessageIndices(payloadString)

			// Check every index for OMCI-message
			for _, index := range omciIndex {
				// Message has to be at least 102 long in this format to be valid
				if index >= 102 {
					var omciString string
					// Check if message has a potential checksum at the end
					if index+16 <= len(payloadString) {
						omciString = payloadString[index-80 : index+16]
					} else {
						omciString = payloadString[index-80 : index+8]
					}

					// Check if selection is all ASCII (OMCI-messages contain only ASCII)
					if utf8string.NewString(omciString).IsASCII() {
						// Decode actual OMCI-message and store result in buffer
						message := decodeOMCIMessage(omciString)
						if message != nil {
							// Extract interfaceId(portnumber) and onuId in front of OMCI-message
							message.InterfaceId, _ = strings.CutPrefix(payloadString[index-102:index-100], "0")
							message.OnuId, _ = strings.CutPrefix(payloadString[index-92:index-90], "0")
							// Add timestamp
							message.Timestamp = packet.Metadata().Timestamp.Local()
							// Add Source and Destination IP and Port
							message.Source = packet.NetworkLayer().NetworkFlow().Src().String() + ":" + strings.Split(packetTCP.SrcPort.String(), "(")[0]
							message.Destination = packet.NetworkLayer().NetworkFlow().Dst().String() + ":" + strings.Split(packetTCP.DstPort.String(), "(")[0]
							// Store message in buffer
							messagesList = append(messagesList, *message)
						}
					}
				}
			}
			return messagesList
		}
	} else {
		// case with OMCI binary directly in ethernet frame, no gRPC, no ONU port etc
		// ethLayer := packet.Layer(layers.LayerTypeEther)
	}
	return nil
}

// Decode OMCI-Messages given as string in format:
// 0001490a01010000c00000000000000000000000000000000000000000000000000000000000000000000028checksum
func decodeOMCIMessage(omciMessage string) *omciMessageStruct {

	// Convert OMCI-Message string into bytes for decoder
	omciMessageBytes, err := hex.DecodeString(omciMessage)

	if err != nil {
		println("ERROR: ", err.Error())
		return nil
	}

	// Build OMCI-Packet for analysis in omci-lib-go
	omciPacket := gp.NewPacket(omciMessageBytes, omci.LayerTypeOMCI, gp.NoCopy)

	// Check if there was a decoding error
	if omciPacket.ErrorLayer() != nil {
		println("DECODING ERROR: ", totalDecodingErrors)
		println(omciPacket.ErrorLayer().Error().Error())
		totalDecodingErrors++

		// Decoding errors can still have partial OMCI layers
		if omciPacket.Layer(omci.LayerTypeOMCI) == nil {
			return nil
		}
	}
	totalOmciMessages++

	// Declare message struct containing information of message
	var message omciMessageStruct
	// Deocde OMCI-Layer
	omciLayer := omciPacket.Layer(omci.LayerTypeOMCI).(*omci.OMCI)

	// Add some basic OMCI-layer information to message struct
	message.MessageNumber = totalOmciMessages
	message.Messagetype = omciLayer.MessageType.String()
	message.TransactionId = omciLayer.TransactionID

	// Decode next layer of OMCI-Layer which is the layer corresponding to the actual message type
	messageLayer := omciPacket.Layer(omciLayer.NextLayerType())

	// Add some basic messagetype information to message struct
	message.MessageLayer = messageLayer
	message.MessageData = make(map[string]any)

	// If there was a decoding error, write error in MessageData
	if omciPacket.ErrorLayer() != nil {
		message.MessageData["Decoding Error"] = omciPacket.ErrorLayer().Error().Error()
	}

	// Determine actual message type during runtime
	// Reflect allows access to specific attributes and methods of the element (message type layer) during runtime
	if reflect.ValueOf(messageLayer).IsValid() {
		messageLayerValue := reflect.ValueOf(messageLayer).Elem()

		// Get basic information about the entity included in the message
		message.EntityClass = messageLayerValue.FieldByName("EntityClass").Interface().(generated.ClassID).String()
		message.InstanceId = messageLayerValue.FieldByName("EntityInstance").Interface().(uint16)

		// Check if message contains a result field representing the status (success/failure) of an ONU command/operation
		if messageLayerValue.FieldByName("Result").IsValid() {
			message.MessageData["Result"] = messageLayerValue.FieldByName("Result").Interface().(generated.Results).String()
		}

		// Some messages like MIB-Upload-Next-Response messages contain a "ReportedME" field containing information about an entity
		reportedME := messageLayerValue.FieldByName("ReportedME")

		// Extract some data if such a field exists, also check if it's a valid pointer because it's pointing to a struct
		if reportedME.IsValid() && reportedME.CanAddr() && reportedME.Addr().CanInterface() {
			managedEntity := reportedME.Addr().Interface().(*generated.ManagedEntity)

			message.MessageData["Attributes"] = managedEntity.GetAttributeValueMap()
			message.MessageData["Class"] = managedEntity.GetClassID().String()
			message.MessageData["Instance"] = managedEntity.GetEntityID()
		}

		// Messages like Alarm Notifications containg an AlarmBitmap indicating the type of alarm
		// This bitmap needs to be decoded to determine the type of alarm it indicates
		if messageLayerValue.FieldByName("AlarmBitmap").IsValid() || messageLayerValue.FieldByName("AlarmBitMap").IsValid() {
			var alarmBitmap []byte
			// Get alarmBitmap
			if messageLayerValue.FieldByName("AlarmBitmap").IsValid() {
				alarmBitmap = messageLayerValue.FieldByName("AlarmBitmap").Bytes()
			} else {
				alarmBitmap = messageLayerValue.FieldByName("AlarmBitMap").Bytes()
			}

			// Each class/type of entity has it's own alarms, therefore the classID needs to be matched with the alarmBitmap
			var alarmClass generated.ClassID
			if messageLayerValue.FieldByName("AlarmEntityClass").IsValid() {
				alarmClass = messageLayerValue.FieldByName("AlarmEntityClass").Interface().(generated.ClassID)
			} else {
				alarmClass = messageLayerValue.FieldByName("EntityClass").Interface().(generated.ClassID)
			}

			// Decode alarmBitmap to determine all alarms that are indicated
			// alarmBitmap is currently 224 bits = 28 bytes long
			// Each bit indicates a different alarm when set to 1
			// Check each bit of alarmBitmap if it is set to 1 by using logical AND operations with control bits set to 1
			// If the result is != 0, the alarm bit is 1
			// Finally use omci-lib-go to match entity class and 1 bits to determine active alarm types
			// Alarm number matches position of bit set to 1
			totalAlarms := 0
			for i := 0; i < omci.AlarmBitmapSize/8; i++ {
				for j := 0; j < 8; j++ {
					if alarmBitmap[i]&byte(math.Pow(2, float64(7-j))) != 0 {
						message.MessageData["Alarm "+strconv.Itoa(totalAlarms)] = getAlarm(alarmClass, i*8+j)
						totalAlarms++
					}
				}
			}
		}
	}
	return &message

}

// Matches entity class ID and alarm number to determine alarm type using omci-lib-go
func getAlarm(class generated.ClassID, alarmNo int) string {

	// Load definition, including alarm map, of managed entity of type referenced by class id
	me, err := generated.LoadManagedEntityDefinition(class)

	if err.GetError() != nil {
		println("ERROR: ", err.Error())

		return "Unknown Class/Alarm"
	}

	// Match alarmNo to alarm type of this specific managed entity class
	alarm, ok := me.GetAlarmMap()[uint8(alarmNo)]

	if ok {
		return "Type " + strconv.Itoa(alarmNo) + ": " + alarm
	} else {
		return "Unknown Alarm No: " + strconv.Itoa(alarmNo)
	}
}

// Print some basic statistics of sniffing and packet/message processing process
func printStats() {
	println("TOTAL PACKETS: ", totalPackets)
	println("SEEN PACKETS: ", seenPackets)
	println("OMCI MESSAGES: ", totalOmciMessages)
	println("DECODING ERRORS: ", totalDecodingErrors)
}

// Resets scanner statistics
func resetStats() {
	totalPackets = 0
	seenPackets = 0
	totalOmciMessages = 0
	totalDecodingErrors = 0
}

// Finds all indices of potential OMCI messages inside a given payload string
func findOMCIMessageIndices(payloadString string) []int {

	// Find all potential OMCI-Message indices
	var omciIndex []int
	start := 0
	for {
		currentIndex := strings.Index(payloadString[start:], "00000028")
		// Break if no index found
		if currentIndex == -1 {
			break
		}
		// Add index to list of all indices
		omciIndex = append(omciIndex, currentIndex+start)
		// Start next iteration after current index
		start += currentIndex + 1
	}
	return omciIndex
}

// OMCI Packet struct containing an omciMessageStruct and its original packet
type omciPacketStruct struct {
	packet       gopacket.Packet
	omciMessages []omciMessageStruct
}

// Adds an omciPacketStruct (packet+omciMessageStruct) to the buffer
func bufferOMCIPacket(omciPacket omciPacketStruct) {

	if len(omciPacketsBuffer) >= bufferSize {
		omciPacketsBuffer = omciPacketsBuffer[(len(omciPacketsBuffer)-bufferSize)+1:]
	}

	omciPacketsBuffer = append(omciPacketsBuffer, omciPacket)
}

// Writes packets containing omci messages from the omci packets buffer to a pcap file.
// Returns the length of the buffer / number of packets written to the pcap and filename
func packetsToPCAP(filename string) (int, string) {

	// Do nothing if buffer is empty
	if omciPacketsBuffer == nil || len(omciPacketsBuffer) <= 0 {
		return 0, ""
	}

	// Default file name
	if filename == "" {
		// Create new pcap filename, use unix timestamp for naming
		currentTime := strconv.Itoa(int(time.Now().Unix()))
		filename = "pcaps/pcap" + currentTime + ".pcap"
	} else {
		// If no .pcap suffix, append .pcap
		if !strings.HasSuffix(filename, ".pcap") {
			filename += ".pcap"
		}
		filename = "pcaps/" + filename
	}

	pcapFile, err := os.Create(filename)

	if err != nil {
		println("ERROR: ", err.Error())
		return 0, ""
	}

	// Create pcap writer
	pcapWriter := pcapgo.NewWriter(pcapFile)
	err = pcapWriter.WriteFileHeader(65536, linkType)

	if err != nil {
		println("ERROR: ", err.Error())
		pcapFile.Close()
		return 0, ""
	}

	// Write packets from omciPacketsBuffer into pcap
	for _, packet := range omciPacketsBuffer {
		err = pcapWriter.WritePacket(packet.packet.Metadata().CaptureInfo, packet.packet.Data())
		if err != nil {
			println("ERROR: ", err.Error())
		}
	}

	pcapFile.Close()

	return len(omciPacketsBuffer), filename
}
