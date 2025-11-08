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

// Declare global variables
let totalMessages = 0;
let totalMessagesElement = document.getElementById("totalMessages");
let totalAlarms = 0;
let totalAlarmsElement = document.getElementById("totalAlarms");
let activePorts = [];
let activeONUs = [];
let allMessages = [];
let messageAccordion = document.getElementById("messages");
let totalOperations = 0;
let failedOperations = 0;
let totalDecodingErrors = 0;
let controllerAddress = "";
let suspiciousOrigin = 0;
let renderStart = null;
let observer;

// Helper function called when rendering is finished in scanPCAP()
function observerHelper()
{
  // Calculate render time and disonnect observer
  let renderEnd = performance.now();
  console.log("Rendered: " + (renderEnd-renderStart) + " ms");
  observer.disconnect();
  renderStart = null;
}

// Send one-time http request to scan configured PCAP-file on server and process JSON response
function scanPCAP()
{
  // Read PCAP file name from textbox
  // var scanPCAP = document.getElementById("scanPCAP").value;
  // if (scanPCAP == "") {scanPCAP = "testfile.pcap";}
  // else if (!scanPCAP.endsWith(".pcap")) {scanPCAP += ".pcap";}

  var scanPCAP = document.getElementById("selectPCAP").value;

  // Create scan config object containing the PCAP file name
  var scanConfig = {"Filename": scanPCAP};
  console.log(scanConfig)

  // Send the PCAP scan request
  var request = {"method": "PUT", "headers": {"Content-Type": "application/json"}, "body": JSON.stringify(scanConfig)};

    fetch("/messages/pcap", request)
    .then((response) => response.json())
    .then((json) =>
        {
          // Create observer to measure render time of message elements
          // Is called whenever a messageAccordion child element is changed
          // Starts measuring time on first element change
          // Calls helper function to finish measurement when no change/render has been detected in 10 ms
          // If observer ends measurement too early inbetween rendering elements, increase timeout
          observer = new MutationObserver(() => {if (renderStart == null) {renderStart = performance.now();} clearTimeout(observer.timeout); observer.timeout = setTimeout(observerHelper, 10);});
          observer.observe(messageAccordion, {childList: true});

          let startTime = performance.now();

          for (var i = 0; i<json.length; i++){
                //console.log(i, json[i])
                processMessage(json[i])
          }
          let endTime = performance.now();
          console.log("Processed messages: " + (endTime-startTime) + " ms");
          // Calculate statistics once after response has been processed
          updateTotalCounters();
          refreshStats();
          clearTimeout(refreshStatsTimer);
          document.getElementById("scanResult").innerText = "Scan successful!\n" + i + " messages scanned from " + scanPCAP;
        })
}

// Incoming SSE connection
let incoming

// Establish an SSE connection to the webserver and create an SSE-handler to process connection
function scanSSE()
{
  if (!scanning)
  {
    // Send start signal request to webserver and then create SSE connection and create and assign SSE-handler
    fetch("/messages/start")
    .then(response => response.text())
    .then(value =>
    {
      if (value.includes("Failed")) {console.log(value); return;}
      else
      {
        incoming = new EventSource("/messages/sse");
        incoming.onmessage = (message) => {handleSSE(message);};
        incoming.addEventListener("close", function(event) { console.log("CLOSING"); incoming.close();});
        incoming.onerror = (err) => {console.error(err);};

        scanning = true;
        // Adjust buttons to stop scanning when clicked
        let button = document.getElementById("button2");
        button.innerText = "Stop Scan";
        button.onclick = stopScan;
        button = document.getElementById("button3");
        button.innerText = "Stop Scan";
        button.onclick = stopScan;
      }
    })
  }
}

// Handles SSE connection and processes incoming messages
function handleSSE(message)
{
  const data = JSON.parse(message.data);

  for (let i = 0; i<data.length; i++)
  {
    processMessage(data[i]);
    //console.log(totalMessages, data[i]);
  }
  updateTotalCounters();
}

// Declare global variables used for request interval
let scanning = false
let fetchTimer
let fetchInterval = 1000;

// Establish the process of sending frequent get-requests to the webserver to request messages
function scanLive()
{
  if (!scanning)
  {
    // Send start signal to webserver and start sending requests in intervals with fetchLive()
    fetch("/messages/start")
    .then(response => response.text())
    .then(value =>
    {
      if (value.includes("Failed")) {console.log(value); return;}
      else
      {
        scanning = true;
        // Adjust buttons to stop scanning when clicked
        let button = document.getElementById("button2");
        button.innerText = "Stop Scan";
        button.onclick = stopScan;
        button = document.getElementById("button3");
        button.innerText = "Stop Scan";
        button.onclick = stopScan;
        fetchLive();
      }
    })
  }
}

// Continuously send get-requests to the webserver to request messages
function fetchLive()
{
  // Send get request to webserver to request all messages currently buffered on the server and then process the JSON response
  fetch("/messages/live")
  .then((response) => response.json())
  .then((json) =>
      {for (let i = 0; i<json.length; i++)
          {
              //console.log(i, json[i])
              processMessage(json[i])
          }
      })
      updateTotalCounters();
      // Continue to call fetchLive every fetchInterval in ms
      if (fetchInterval > 0) {fetchTimer = setTimeout(fetchLive, fetchInterval);}
}

// Stop any scanning currently in progress
async function stopScan()
{
  if (scanning)
  {
    // Clear timeout and thereby stop calling fetchLive()
    clearTimeout(fetchTimer);
    scanning = false;
    // Send stop message to webserver to stop sniffer and close channels
    await fetch("/messages/stop");

    // Adjust buttons to re-enable starting scans
    let button = document.getElementById("button2");
    button.innerText = "Scan Network";
    button.onclick = scanLive;
    button = document.getElementById("button3");
    button.innerText = "Scan Network SSE";
    button.onclick = scanSSE;
  }
}

// Initialize first color of sccordion elements
let dark = true

// Add an OMCI-message to the message accordion by creating an accordion element
function addMessage(x, y)
{
  totalMessages++;
  
  // Figure out color of current accordion element
  var color = "light";

  if (dark)
  {
    color = "secondary";
  }

  if (x.Messagetype.includes("Alarm Notification"))
  {
    color = "danger";
    totalAlarms++;
  }

  dark = !dark;

  // Create base accordion item container
  var cardDiv = document.createElement("div");
  cardDiv.className = "accordion-item text-bg-" + color + " border-" + color;
  cardDiv.id = "accordion-item" + totalMessages;

  // Create accordion header
  var cardHeaderDiv = document.createElement("h4");
  cardHeaderDiv.className = "accordion-header";
  cardHeaderDiv.id = "collapse-header" + totalMessages;

  // Add button to collapse body
  var cardA = document.createElement("button");
  cardA.className = "accordion-button collapsed text-bg-" + color + " border-" + color;
  cardA.id = "accordion-button" + totalMessages;

  // Set button attributes to enable collapsing
  cardA.setAttribute("data-bs-toggle", "collapse");
  cardA.setAttribute("type", "button");
  cardA.setAttribute("data-bs-target", "#collapse" + totalMessages);
  cardA.setAttribute("aria-expanded", "false");
  cardA.setAttribute("aria-controls", "#collapse" + totalMessages);

  // Build Header List
  var headerList = document.createElement("ul");
  headerList.className = "list-group list-group-horizontal d-flex overflow-auto"

  // Add messagenumber to header
  var messageNumber = document.createElement("li");
  messageNumber.className = "list-group-item text-bg-" + color;
  messageNumber.innerText = totalMessages;
  headerList.appendChild(messageNumber);

  // Add messagetype to header
  var messageType = document.createElement("li");
  messageType.className = "list-group-item text-bg-" + color;
  messageType.innerText = x.Messagetype;
  headerList.appendChild(messageType);

  // Add interface id (port number) to header
  var InterfaceId = document.createElement("li");
  InterfaceId.className = "list-group-item text-bg-" + color;
  InterfaceId.innerText = "Interface ID: " + x.InterfaceId;
  headerList.appendChild(InterfaceId);

  // Add ONU ID to header
  var OnuId = document.createElement("li");
  OnuId.className = "list-group-item text-bg-" + color;
  OnuId.innerText = "Onu ID: " + x.OnuId;
  headerList.appendChild(OnuId);

  // Add transaction ID to header
  var TransactionId = document.createElement("li");
  TransactionId.className = "list-group-item text-bg-" + color;
  TransactionId.innerText = "Transaction ID: " + x.TransactionId;
  headerList.appendChild(TransactionId);

  // Add timestamp to header
  var timestampElement = document.createElement("li");
  timestampElement.className = "list-group-item text-bg-" + color;
  var timestamp = new Date(x.Timestamp);
  // Extract milliseconds from timestamp because JS doesn't support ms resolution natively
  var i = x.Timestamp.indexOf(".");
  var j = x.Timestamp.indexOf("+");
  var tNanos = x.Timestamp.substring(i, j);
  timestampElement.innerText = "Timestamp: " + timestamp.toLocaleString() + tNanos;
  headerList.appendChild(timestampElement);

  // Add source and destination IP:Port to header
  var srcElement = document.createElement("li");
  srcElement.className = "list-group-item text-bg-" + color;
  srcElement.innerText = "Source: " + x.Source;
  headerList.appendChild(srcElement);

  var dstElement = document.createElement("li");
  dstElement.className = "list-group-item text-bg-" + color;
  dstElement.innerText = "Destination: " + x.Destination;
  headerList.appendChild(dstElement);

  // Add direction depending on message type (request = downstream)
  var directionElement = document.createElement("li");
  directionElement.className = "list-group-item text-bg-" + color;
  if (x.Messagetype.includes("Request")) {directionElement.innerText = "Direction: Downstream"; x["Direction"] = "Downstream";}
  else {directionElement.innerText = "Direction: Upstream"; x["Direction"] = "Upstream";}
  headerList.appendChild(directionElement);

  // Append accordion header to accordion element
  cardA.appendChild(headerList)

  // Create collapse element
  var collapseDiv = document.createElement("div");
  collapseDiv.id = "collapse" + totalMessages;
  collapseDiv.className = "accordion-collapse collapse";
  //collapseDiv.setAttribute("data-bs-parent", "#messages");
  collapseDiv.setAttribute("aria-labelledby", "collapse-header" + totalMessages)

  // Create accordion body base container
  var cardBodyDiv = document.createElement("div");
  cardBodyDiv.className = "accordion-body";

  //Build Body List
  var list = document.createElement("ul");
  list.className = "list-group list-group-horizontal d-flex overflow-auto";

  // Add entity class to body
  var entityClass = document.createElement("li");
  entityClass.className = "list-group-item text-bg-" + color;
  entityClass.innerText = "EntityClass: " + x.EntityClass;
  list.appendChild(entityClass);

  // Add entity instance to body
  var entityInstance = document.createElement("li");
  entityInstance.className = "list-group-item text-bg-" + color;
  entityInstance.innerText = "EntityInstance: " + x.InstanceId;
  list.appendChild(entityInstance);

  // Get basic information from Layer, excluding some fields
  const excludedFields = ["Layer", "Contents", "Payload", "MsgLayerType", "Attributes", "EntityClass", "EntityInstance", "ReportedME", "AdditionalMEs", "RelaxedErrors"];
  const base64Fields = ["EquipmentId", "SerialNumber", "VendorId", "Version", "ExpectedEquipmentId", "ActualEquipmentId", "OltVendorId"];

  // Create list element for each field in MessageLayer that has not already been processed explicitly
  for (let data in x.MessageLayer)
  {
    if (!excludedFields.includes(data))
    {
      let messageData = document.createElement("li");
      messageData.className = "list-group-item text-bg-" + color;
      // If the current field is the "Result" field, get additional result status information from corresponding MessageData field
      if (data == "Result") {messageData.innerText = data + ": " + x.MessageLayer[data] + " (" + x.MessageData["Result"] + ")";}
      else {messageData.innerText = data + ": " + x.MessageLayer[data];}
      list.appendChild(messageData);
    }
  }

  // Append entire list to body container
  cardBodyDiv.appendChild(list);

  // Create another list if there is a list of Attributes element inside MessageLayer
  if (x.MessageLayer != null && x.MessageLayer["Attributes"] != null)
  {
    // Create attribute list
    let attributeList = document.createElement("ul");
    attributeList.className = "list-group list-group-horizontal d-flex overflow-auto";

    // Create and append a list element for each attribute in Attributes field
    for (let attribute in x.MessageLayer["Attributes"])
    {
        let attributeElement = document.createElement("li");
        attributeElement.className = "list-group-item text-bg-" + color;
        // If the attribute is part of a list of attributes encoded in base64, decode that field before appending
        if (base64Fields.includes(attribute))
        {
          attributeElement.innerText = attribute + ": " + atob(x.MessageLayer["Attributes"][attribute]);
        }
        else
        {
          attributeElement.innerText = attribute + ": " + x.MessageLayer["Attributes"][attribute];
        }
        attributeList.appendChild(attributeElement);
    }

    // Append attribute list to body container
    cardBodyDiv.appendChild(attributeList);
  }

  //Get Information from Data-Map, if it exists, usually a managed entity
  if (x.MessageData != null)
  {
    // Create data/attribute list
    let list2 = document.createElement("ul");
    list2.className = "list-group list-group-horizontal d-flex overflow-auto";

    // Explicitly process entity class
    if (x.MessageData["Class"] != null)
    {
      let reportedEntityClass = document.createElement("li");
      reportedEntityClass.className = "list-group-item text-bg-" + color;
      reportedEntityClass.innerText = "ReportedEntityClass: " + x.MessageData.Class;
      list2.appendChild(reportedEntityClass);
    }

    // Explicitly process entity instance
    if (x.MessageData["Instance"] != null)
    {
      let reportedEntityInstance = document.createElement("li");
      reportedEntityInstance.className = "list-group-item text-bg-" + color;
      reportedEntityInstance.innerText = "ReportedEntityInstance: " + x.MessageData.Instance;
      list2.appendChild(reportedEntityInstance);
    }

    // Explicitly process list of attributes 
    if (x.MessageData["Attributes"] != null)
    {
      for (let attribute in x.MessageData["Attributes"])
        {
          let attributeElement = document.createElement("li");
          attributeElement.className = "list-group-item text-bg-" + color;
          // If the attribute is part of a list of attributes encoded in base64, decode that field before appending
          if (base64Fields.includes(attribute))
          {
            attributeElement.innerText = attribute + ": " + atob(x.MessageData["Attributes"][attribute]);
          }
          else
          {
            attributeElement.innerText = attribute + ": " + x.MessageData["Attributes"][attribute];
          }
          list2.appendChild(attributeElement);
        }
    }

    //Exclude explicitly processed fields
    const excludedFields2 = ["Attributes", "Instance", "Class", "Result"];

    // Process remaining fields in MessageData, like alarms
    for (let data in x.MessageData)
    {
      if (!excludedFields2.includes(data))
      {
        let messageData = document.createElement("li");
        messageData.className = "list-group-item text-bg-" + color;
        messageData.innerText = data + ": " + x.MessageData[data]
        list2.appendChild(messageData);
      }
    }

    // Append MessageData list to body
    cardBodyDiv.appendChild(list2);
  }

  // Append remaining elements
  cardHeaderDiv.appendChild(cardA);
  cardDiv.appendChild(cardHeaderDiv);

  collapseDiv.appendChild(cardBodyDiv);
  cardDiv.appendChild(collapseDiv);

  // If there is a Result field, count operations, check if opeartion was successful, and recolor message if it failed
  if (x.MessageLayer != null && x.MessageLayer["Result"] != null)
  {
    totalOperations++;
    if (x.MessageLayer["Result"] != 0)
    {
      failedOperations++;
      recolorMessage(cardDiv, "peru");
    }
  }

  // Check if there was a decoding error and recolor message
  if (x.MessageData != null && x.MessageData["Decoding Error"] != null)
  {
    totalDecodingErrors++;
    recolorMessage(cardDiv, "purple")
  }

  // Find SDN-controller address and check current message's origin
  // (address is destination of upstream messages)
  if (controllerAddress == "" && x.Direction == "Upstream") {controllerAddress = x.Destination;}
  if (controllerAddress != "" && x.Direction == "Downstream" && x.Source != controllerAddress)
  {
    suspiciousOrigin++;
    recolorMessage(srcElement, "magenta");
  }

  // Append entire accordion element to main accordion container
  if (ascending) {y.appendChild(cardDiv);}
  else {y.prepend(cardDiv);}

  // Check if a previously missing message has been processed
  checkMissingMessages(x);  //Disable if too slow! refreshStats and analyzeTransactions also check periodically
}

// Initialize global variables for filtering
let onuFilter = "";
let appliedFilter = "";
let stringFilter = "";
document.getElementById("inputFilterForm").addEventListener("submit", e => e.preventDefault());
let allFilters = [];

// Process an incoming message (JSON)
function processMessage(x)
{
  // Add the message to global message buffer
  allMessages.push(x);

  // If an interfaceId/port is encountered for the first time, add a filterItem for port-filtering
  if (!activePorts.some(e => e.port == x.InterfaceId))
  {
    var portData = {"port": x.InterfaceId, "onu": "", "count": 0};
    activePorts.push(portData);
    document.getElementById("activePorts").innerText="Active Ports: " + activePorts.length;

    addFilterItem(portData);
  }

  // Update counter for number of messages on current port
  activePorts.find(e => e.port == x.InterfaceId).count++;

  // If an ONU is encountered for the first time, add a filterItem for ONU-filtering
  if (!activeONUs.some(e => e.port == x.InterfaceId && e.onu == x.OnuId))
  {
    var onuData = {"port": x.InterfaceId, "onu": x.OnuId, "count": 0};
    activeONUs.push(onuData);
    document.getElementById("activeONUs").innerText="Active ONUs: " + activeONUs.length;

    addFilterItem(onuData);
  }

  // Update counter for number of messages on current ONU
  activeONUs.find(e => e.port == x.InterfaceId && e.onu == x.OnuId).count++;

  // If current message passes filter, add message to message accordion
  if (filterONU(x) && filterString(x)) {addMessage(x, messageAccordion);}
}

// Adds a filterItem on the filter modal for port/onu filtering
function addFilterItem(onuData)
{
  // Create filter button as list element
  var listItem = document.createElement("button");
  listItem.className = "list-group-item list-group-item-action";
  listItem.setAttribute("type", "button");
  var id = "filterButton" + onuData.port + onuData.onu;
  listItem.id = id;
  // Write data of port/onu into data field for access when clicked
  listItem.setAttribute("data-onudata", JSON.stringify(onuData));
  // When filterItem is clicked, mark it active and de-mark other filterItems
  listItem.onclick = (event) => {
    var e = document.getElementById(id);
    e.classList.toggle("active");
    for (let filter of allFilters)
    {
      if (filter.id != id)
      {
        filter.className = filter.className.replaceAll(" active", "");
      }
    }
    // If current/clicked filterItem is active now, write port/onu data into filter-to-be-applied
    if(e.className.includes("active")) {onuFilter = JSON.parse(event.target.getAttribute("data-onudata"));}
    else {onuFilter = "";}console.log(onuFilter)};

  // Write filterItem text
  if(onuData.onu != "") {listItem.innerText = "Port ID: " + onuData.port + " | ONU ID: " + onuData.onu + " | No. Messages: " + 0;}
  else {listItem.innerText = "Port ID: " + onuData.port + " | No. Messages: " + 0;}

  // Add filterItem to list of all filters
  allFilters.push(listItem);

  // Append filterItem to list of filter in filter modal
  document.getElementById("filterModalList").appendChild(listItem);
}

// Global variables related to refreshinf filterItems
let filterRefreshTimer;
let filterRefreshInterval = 0;
// Don't refresh webpage when pressing enter while in textbox
document.getElementById("filterRefreshForm").addEventListener("submit", e => e.preventDefault());

// Refreshes all filterItems by sorting newly created filterItems and updating message counters
function refreshFilters()
{
  allFilters.sort(sortFilters);
  var currentList = document.getElementById("filterModalList");
  var newList = currentList.cloneNode(false);
  // Newly append sorted filterItems, including new filterItems
  for (let x = 0; x < allFilters.length; x++)
  {
    updateCounter(allFilters[x]);
    newList.appendChild(allFilters[x]);
  }
  // Replace old filter list with new filter list
  currentList.parentNode.replaceChild(newList, currentList);
  // Refresh filters continuously if desired
  if (filterRefreshInterval > 0) {filterRefreshTimer = setTimeout(refreshFilters, filterRefreshInterval);}
}

// Stops continuous refreshing of filter list
function stopRefreshFilters()
{
  clearTimeout(filterRefreshTimer);
}

// Sets interval in which to refresh filter list
function setFilterRefreshInterval()
{
  // Extract value entered in textbox and apply it if valid
  var newTimer = document.getElementById("filterRefresh").value;
  if (newTimer != "" && !isNaN(newTimer)) {filterRefreshInterval = newTimer;}
}

// Compares and sorts two filterItems along their port ids and then along their onu ids
function sortFilters(a, b)
{
  var dataA = JSON.parse(a.getAttribute("data-onudata"));
  var dataB = JSON.parse(b.getAttribute("data-onudata"));

  if (dataA.port < dataB.port) {return -1;}
  if (dataA.port > dataB.port) {return 1;}
  if (dataA.onu < dataB.onu) {return -1;}
  if (dataA.onu > dataB.onu) {return 1;}

  return 0;
}

// Updates message counter for a filterItem
function updateCounter(x)
{
  // Get onuData for matching
  var onuData = JSON.parse(x.getAttribute("data-onudata"));

  // Retrieve counter from matching onuData in ONU-buffer
  if (onuData.onu != "") {onuData.count = activeONUs.find(e => e.port == onuData.port && e.onu == onuData.onu).count;}

  // If onu field is empty, current filterItem is a port filter, so retrieve counter from matchin port in port buffer instead
  else {onuData.count = activePorts.find(e => e.port == onuData.port).count;}

  // Write new counter
  x.setAttribute("data-onudata", JSON.stringify(onuData));
  x.innerText = x.innerText.slice(0, x.innerText.indexOf(" | No. Messages: ")) + " | No. Messages: " + onuData.count;
}

// Applies port/onu/string filter on all received messages
function applyFilter()
{
  // Reset some variables
  stopRefreshFilters();
  totalMessages = 0;
  totalAlarms = 0;
  totalDecodingErrors = 0;
  totalOperations = 0;
  failedOperations = 0;
  suspiciousOrigin = 0;
  dark = true;
  // Write currently selected filter into applied filter to signal actual application of filter
  appliedFilter = onuFilter;
  // Retrieve string for filtering from textbox
  stringFilter = document.getElementById("inputFilter").value.toLowerCase();
  console.log(stringFilter);

  // Create new main accordion container
  var newMessages = messageAccordion.cloneNode(false);

  // Apply filters to all messages
  for (let message of allMessages)
  {
    // Add message to accordion container if filter is passed
    if (filterONU(message) && filterString(message)) {addMessage(message, newMessages);}
  }
  updateTotalCounters();
  // Replace old main accordion container with new one
  messageAccordion.parentNode.replaceChild(newMessages, messageAccordion);
  messageAccordion = newMessages;

  // Refresh statistics once
  refreshStats();
  clearTimeout(refreshStatsTimer);
}

// Filters a message in accordance to it's port and onu ids, returns true if it passes
function filterONU(a)
{
  return appliedFilter == "" || appliedFilter.port == a.InterfaceId && (appliedFilter.onu == "" || appliedFilter.onu == a.OnuId);
}

// Filters a message in accordance to the string contained in stringFilter, returns true if it passes
function filterString(a)
{
  if (stringFilter == "") {return true;}

  // Iterate over all keys/fields and check if stringFilter is present
  for (let field in a)
  {
    // If current field is an object, recursively call filterString
    if (a[field] != null && typeof(a[field]) === "object")
    {
      if(filterString(a[field]))
      {
        return true;
      }
    }

    // Check if current key or value contains stringFilter
    else if ((field + ": " + String(a[field])).toLowerCase().includes(stringFilter))
    {
      return true;
    }
  }
  return false;
}

// Updates main counters for total number of messages and alarms in header
function updateTotalCounters()
{
  totalMessagesElement.innerText="Total Messages: " + totalMessages;
  totalAlarmsElement.innerText="Total Alarms: " + totalAlarms;
}

// Global variables related to calculating statistics
let refreshStatsTimer;
let statsRefreshInterval = 0;
// Don't refresh webpage when pressing enter while in textbox
document.getElementById("statsRefreshForm").addEventListener("submit", e => e.preventDefault());
let missingMessagesList = [];
let skippedTIDsList = [];

// Recalculates and refreshes statistics for given (filtered) messages
function refreshStats()
{
  // Stop automatic refresh
  clearTimeout(refreshStatsTimer);
  var startTime = performance.now();

  // Filter messages for analysis. DON'T filter using stringFilter because it invalidates context-dependant analysis
  // Only analyze for a port/onu
  var filteredMessages = [];
  if (appliedFilter != "") {filteredMessages = allMessages.filter(filterONU);}
  else {filteredMessages = allMessages;}

  if (filteredMessages.length > 0)
  {
    // Call main analysis function and store results in object
    let transactionsData = analyzeTransactions(filteredMessages);
    
    // Write results into statistics list elements
    document.getElementById("statsTotalMessages").innerText = "Total Messages: " + totalMessages;
    document.getElementById("statsTotalAlarms").innerText = "Total Alarms: " + totalAlarms;
    document.getElementById("statsActivePorts").innerText = "Active Ports: " + activePorts.length;
    document.getElementById("statsActiveONUs").innerText = "Active ONUs: " + activeONUs.length;
    document.getElementById("statsTotalTransactions").innerText = "Total Transactions: " + transactionsData.total;
    document.getElementById("statsMissingMessages").innerText = "Missing Messages: " + transactionsData.missing;
    document.getElementById("statsSkippedTIDs").innerText = "Skipped TIDs: " + transactionsData.skipped;
    document.getElementById("statsRequestResponseSwapped").innerText = "Requests/Responses Swapped: " + transactionsData.rrswapped;
    document.getElementById("statsSwappedTransactions").innerText = "Transactions Out Of Sequence: " + transactionsData.tidswapped;
    document.getElementById("statsUnorderedTimestamps").innerText = "Timestamps Out Of Sequence: " + transactionsData.unorderedTimes;
    document.getElementById("statsMPS").innerText = "Messages / Second: " + transactionsData.mps;
    document.getElementById("statsResponseTime").innerText = "Average Response Time (ms): " + transactionsData.responseTime + " Max: " + transactionsData.maxResponseTime.responseTime + " @" + transactionsData.maxResponseTime.index;
    document.getElementById("statsFailedOperations").innerText = "Failed (Total) ONU Operations: " + failedOperations + " (" + totalOperations + ")";
    document.getElementById("statsDecodingErrors").innerText = "Decoding Errors: " + totalDecodingErrors;
    document.getElementById("statsSuspiciousOrigins").innerText = "Suspicious Origins: " + suspiciousOrigin;
    document.getElementById("statsController").innerText = "SDN-Controller Address: " + controllerAddress;

    let skippedTIDsText = "Skipped TIDs: " + transactionsData.skipped;

    for (let x = 0; x < skippedTIDsList.length; x++)
    {
      if (x == 0) {skippedTIDsText += " @";}
      skippedTIDsText += skippedTIDsList[x]+ ", ";
    }

    document.getElementById("statsSkippedTIDs").innerText = skippedTIDsText;
  }

  // Recalculate/Refresh statisitcs if desired
  if (statsRefreshInterval > 0) {refreshStatsTimer = setTimeout(refreshStats, statsRefreshInterval);}
  var endTime = performance.now();
  console.log("Analyzed messages: " + (endTime-startTime) + " ms");
}

// Stops continuous refreshing of statistics
function stopRefreshStats()
{
  clearTimeout(refreshStatsTimer);
}

// Sets interval in which to refresh statistics
function setStatsRefreshInterval()
{
  // Extract value entered in textbox and apply it if valid
  var newTimer = document.getElementById("statsRefresh").value;
  if (newTimer != "" && !isNaN(newTimer)) {statsRefreshInterval = newTimer;}
}

function triggerJsonDownload(obj, filename){
  var type_str = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(obj));
  var a_node = document.createElement('a');
  a_node.setAttribute("href", type_str);
  a_node.setAttribute("download", filename + ".json");
  document.body.appendChild(a_node);
  a_node.click();
  a_node.remove();
}

// Analyzes filtered messages and the transactions they represent
function analyzeTransactions(messages)
{
  // Initialize basic statistics and data
  var transactions = [];
  var transactionsCount = 0;
  var index = 0;
  var requestResponseSwapped = 0;
  var unorderedTimestamps = 0;
  var previousTimestamp = null;
  var previousNanoseconds = null;
  var firstTimestamp = new Date(messages[0].Timestamp);
  var lastTimestamp = new Date(messages[messages.length-1].Timestamp);

  // MESSAGE ANALYSIS
  // Iterate over all messages for analysis
  for (let message of messages)
  {
    checkMissingMessages(message);
    index++;
    // Check if current message is a request or a response or both/neither
    let isRequest = message.Messagetype.includes("Request") || message.Messagetype.includes("Alarm");
    let isResponse = message.Messagetype.includes("Response") || message.Messagetype.includes("Alarm");

    // Extract milliseconds from timestamp because JS doesn't support ms resolution natively
    let currentTimestamp = new Date(message.Timestamp);
    let currentTimeIndex = message.Timestamp.indexOf(".");
    let currentTimeIndexEnd = message.Timestamp.indexOf("+");
    let currentNanoseconds = parseInt(message.Timestamp.substring(currentTimeIndex, currentTimeIndexEnd), 10);

    // Create transaction element for current message
    // A transaction refers to a pair of request and response messages of one set of port id, onu id, and tid
    let transaction = {"index": index, "port": message.InterfaceId, "onu": message.OnuId, "tid": message.TransactionId, "request": null, "response": null};

    // Write timestamps into transaction so that we can calculate how long a response took
    if (isRequest) {transaction.request = currentTimestamp;}
    if (isResponse) {transaction.response = currentTimestamp;}

    // Check if a message of this current transaction has already been encountered, which means the transaction is already stored
    let foundTransaction = transactions.find(e => e.port == transaction.port && e.onu == transaction.onu && e.tid == transaction.tid);

    // If the current transaction is new, add it to the list of transactions
    if (foundTransaction == null)
    {
      transactionsCount = transactions.push(transaction);
    }

    // If another message of this transaction message pair has already been encountered, process it further
    else
    {
      // If the current message is a request, a response has already been encountered, which is probably bad
      if (isRequest)
      {
        // If that's the case, count and mark a swapped request/response
        if (foundTransaction.request == null && foundTransaction.response != null)
        {
          requestResponseSwapped++;
          recolorMessage(document.getElementById("accordion-item" + transaction.index, "info"));
        } 
        foundTransaction.request = currentTimestamp;
      }
      if (isResponse) {foundTransaction.response = currentTimestamp;}
    }

    // If the previous message's timestamp is higher than the current message's timestamp, they are ordered incorrectly
    if (previousTimestamp != null && previousNanoseconds != null && (previousTimestamp > currentTimestamp || (previousTimestamp == currentTimestamp && previousNanoseconds > currentNanoseconds)))
    {
      // Count and color unordered timestamped messages
      unorderedTimestamps++;
      recolorMessage(document.getElementById("accordion-item" + (index-1)), "info");
      recolorMessage(document.getElementById("accordion-item" + index), "info");
    }
    previousTimestamp = currentTimestamp;
    previousNanoseconds = currentNanoseconds;

    // Find earliest and latest timestamps
    if (firstTimestamp == null || currentTimestamp < firstTimestamp) {firstTimestamp = currentTimestamp;}
    if (lastTimestamp == null || currentTimestamp > lastTimestamp) {lastTimestamp = currentTimestamp;}
  }

  // TRANSACTION ANALYSIS
  // Variables related to transaction analysis
  var missingMessages = 0;
  missingMessagesList = [];
  var swappedTransactionIDs = 0;
  var previousTransactions = [];
  var totalResponseTime = 0;
  var maxResponseTime = {"index": 0, "responseTime": 0};

  // Iterate over all transactions
  for (let transaction of transactions)
  {
    // Check if request or response is missing
    if (transaction.request == null || transaction.response == null)
    {
      // Count and color message missing it's corresponding message
      missingMessages++;
      missingMessagesList.push(transaction);

      recolorMessage(document.getElementById("accordion-item" + transaction.index), "warning");
    }

    // If request and response exists, calculate response time and note max response time
    else
    {
      let responseTime = transaction.response - transaction.request;
      totalResponseTime += responseTime;
      if (maxResponseTime.responseTime < responseTime)
      {
        maxResponseTime.responseTime = responseTime;
        maxResponseTime.index = transaction.index;
      }

      if (responseTime > 1000)
      {
        recolorMessage(document.getElementById("accordion-item" + transaction.index), "maroon");
      }
    }

    // Check if transaction ids are out of sequence, tid 0 and 1 are reserved
    if (transaction.tid > 1)
    {
      // Get previous transaction for port/onu set if present or save current transaction if not present
      let previous = previousTransactions.find(e => e.port == transaction.port && e.onu == transaction.onu);

      if (previous == null)
      {
        previousTransactions.push({"index": transaction.index, "port": transaction.port, "onu": transaction.onu, "tid": transaction.id});
      }
  
      else
      {
        // If a previous transaction exists, check that it is in correct order and count/color it if it isn't
        if (previous.tid > transaction.tid)
        {
          swappedTransactionIDs++;
          recolorMessage(document.getElementById("accordion-item" + transaction.index), "info");
          recolorMessage(document.getElementById("accordion-item" + previous.index), "info");
        }
        previous.tid = transaction.tid;
        previous.index = transaction.index;
      }
    }
  }
  
  // Calculate average and max response times
  var averageResponseTime = (totalResponseTime / transactions.length).toFixed(2);
  maxResponseTime.responseTime = maxResponseTime.responseTime.toFixed(2);

  // Sort transactions along their port id then onu id then tid
  transactions.sort(sortTransactions);

  // Variables related to transaction id analysis
  var skippedTIDs = 0;
  var previousTransaction = "";
  skippedTIDsList = [];

  // DEBUGGING: trigger json download
  // triggerJsonDownload(transactions, "all_transactions.json");

  // Iterate over now sorted transactions to check whether tids were skipped
  for (let transaction of transactions) {
    // Overwrite previous transaction if next port/onu or reserved tid is encountered
    if (previousTransaction == "" || previousTransaction.port != transaction.port || previousTransaction.onu != transaction.onu || previousTransaction.tid <= 1 || transaction.tid <= 1)
    {
      previousTransaction = transaction;
    } else
    {
      // If difference is larger than 1, at least one tid has been skipped
      if (transaction.tid - previousTransaction.tid > 1)
      {
        skippedTIDs++;
        skippedTIDsList.push(previousTransaction.tid + "-" + transaction.tid);
      }

      previousTransaction = transaction;
    }
  }

  // Calculate messages per second
  var messagesPerSecond = (messages.length / (lastTimestamp - firstTimestamp)*1000).toFixed(2);

  // Return object containing analysis data
  return {"total": transactionsCount, "missing": missingMessages, "skipped": skippedTIDs, "rrswapped": requestResponseSwapped, "tidswapped": swappedTransactionIDs, "unorderedTimes": unorderedTimestamps, "mps": messagesPerSecond, "responseTime": averageResponseTime, "maxResponseTime": maxResponseTime};
}

// Colors an element x in color if it exists
function recolorMessage(x, color)
{
  if (x != null)
  {
    var element = x;

    // Orange-ish color for failed ONU commands/operations has no Bootstrap class item
    if (color == "peru" || color == "purple" || color == "magenta" || color == "maroon")
    {
      element.classList.remove("text-bg-secondary")
      element.classList.remove("border-secondary")
      element.classList.remove("text-bg-light")
      element.classList.remove("border-light")

      element.style.backgroundColor = color;
      element.style.color = "white";
    }

    // Replace Bootstrap color class item
    else
    {
      element.classList.replace("text-bg-secondary", "text-bg-" + color);
      element.classList.replace("border-secondary", "border-" + color);
      element.classList.replace("text-bg-light", "text-bg-" + color);
      element.classList.replace("border-light", "border-" + color);
    }

    // Call function recursively to color all children and children's children
    for (let child of element.children)
    {
      recolorMessage(child, color);
    }
  }
}

// Checks if the current message was missing before and reverts coloring
function checkMissingMessages(message)
{
  // Checks if the current message is the counterpart of a message/transaction which previously had a missing message
  var missingMessage = missingMessagesList.find(e => e.port == message.InterfaceId && e.onu == message.OnuId && e.tid == message.TransactionId);

  // If that's the case
  if (missingMessage != null)
  {
    // Set request/response accordingly
    let isRequest = message.Messagetype.includes("Request") || message.Messagetype.includes("Alarm");
    let isResponse = message.Messagetype.includes("Response") || message.Messagetype.includes("Alarm");

    if (isRequest) {missingMessage.request = true;}
    if (isResponse) {missingMessage.response = true;}

    // If this transaction's request and response fields are now not null, so either a timestamp or true, the missing message has been found
    if (missingMessage.request != null && missingMessage.response != null)
    {
      // Remove coloring and remove missing message element from list
      decolorMessage(document.getElementById("accordion-item" + missingMessage.index), missingMessage.index);
      missingMessagesList.splice(missingMessagesList.findIndex(e => e === missingMessage), 1);
    }
  }
}

// Removes an element's special coloring
function decolorMessage(x, index)
{
  if (x != null)
  {
    var element = x;

    // If index is divisable by 2, it's supposed to be light
    if (index % 2 == 0)
    {
      element.classList.replace("text-bg-warning", "text-bg-light");
      element.classList.replace("border-warning", "border-light");
    }

    // Else dark
    else
    {
      element.classList.replace("text-bg-warning", "text-bg-secondary");
      element.classList.replace("border-warning", "border-secondary");
    }

    // Recursively decolor all children and children's children
    for (let child of element.children)
    {
      decolorMessage(child, index);
    }
  }
}

// Compares and sorts two transactions along their port ids, then onu ids, then tids
function sortTransactions(a, b)
{
  if (a.port < b.port) {return -1;}
  if (a.port > b.port) {return 1;}
  if (a.onu < b.onu) {return -1;}
  if (a.onu > b.onu) {return 1;}
  if (a.tid < b.tid) {return -1;}
  if (a.tid > b.tid) {return 1;}

  return 0;
}

// Applies config entered in the config modal window
function applyConfig()
{
  // Read all entered config values from their textboxes
  var configInterface = document.getElementById("configInterface").value;
  var configFilter = document.getElementById("configFilter").value;
  var configPackets = document.getElementById("configPackets").value;
  var configInterval = document.getElementById("configInterval").value;
  var configBuffer = document.getElementById("configBuffer").value;

  // Set default values if the entered values are invalid
  if (configInterface == "") {configInterface = "ens18";}
  if (configFilter == "") {configFilter = "tcp && port 9191";}
  if (configPackets == "" || isNaN(configPackets)) {configPackets = "100";}
  if (configInterval == "" || isNaN(configInterval)) {configInterval = "1000";}
  if (configBuffer == "" || isNaN(configBuffer)) {configBuffer = "10000";}

  // Directly apply interval for fetchLive()
  fetchInterval = parseInt(configInterval);
  // Create config object containing all config parameters
  var config = {"Iface": configInterface, "Filter": configFilter, "Packets": configPackets, "Interval":configInterval, "Buffer":configBuffer};
  console.log(config);
  // Send the config object to the webserver to be applied
  sendConfig(config);
}

// Sends a config object to the webserver to be applied
function sendConfig(config)
{
  var request = {"method": "PUT", "headers": {"Content-Type": "application/json"}, "body": JSON.stringify(config)};
  fetch("/messages/config", request);
}

// Sends an export to pcap request to the webserver
function exportPCAP()
{
  // Read PCAP file name from textbox
  var exportPCAP = document.getElementById("exportPCAP").value;
  if (exportPCAP != "" && !exportPCAP.endsWith(".pcap")) {exportPCAP += ".pcap";}

  // Create export config object containing the PCAP file name
  var exportConfig = {"Filename": exportPCAP};
  console.log(exportConfig)

  // Send the PCAP export request
  var request = {"method": "PUT", "headers": {"Content-Type": "application/json"}, "body": JSON.stringify(exportConfig)};
  fetch("/messages/export", request)
  .then(response => response.text())
  .then(value => {console.log(value); document.getElementById("exportResult").innerText = value;})
}

// Stops all live scans and reloads the page to clear everything
async function reloadPage()
{
  await stopScan();
  location.reload(true);
}

// Sends a request to inject a message
function inject()
{
  // Read all entered injection parameters from their textboxes
  var injectionType = document.getElementById("injectionType").value;
  var injectionIP = document.getElementById("injectionIP").value;
  var injectionTimeout = document.getElementById("injectionTimeout").value;
  var injectionPort = document.getElementById("injectionPort").value;
  var injectionOnu = document.getElementById("injectionOnu").value;
  var injectionTid = document.getElementById("injectionTid").value;
  var injectionInstance = document.getElementById("injectionInstance").value;
  var injectionClass = document.getElementById("injectionClass").value;
  var injectionCommands = document.getElementById("injectionCommands").value;
  var injectionAttributes = document.getElementById("injectionAttributes").value;
  var injectionMessage = document.getElementById("injectionMessage").value;

  // Set default values if the entered values are invalid
  if (injectionType == "") {injectionType = "OLT_GetOnuInfo";}
  if (injectionIP == "") {injectionIP = "172.16.5.18:9191";}
  if (injectionTimeout == "" || isNaN(injectionTimeout)) {injectionTimeout = "5";}
  if (injectionPort == "" || isNaN(injectionPort)) {injectionPort = "1";}
  if (injectionOnu == "" || isNaN(injectionOnu)) {injectionOnu = "1";}
  if (injectionTid == "" || isNaN(injectionTid)) {injectionTid = "1234";}
  if (injectionInstance == "" || isNaN(injectionInstance)) {injectionInstance = "0";}
  if (injectionClass == "" || isNaN(injectionClass)) {injectionClass = "2";}
  if (injectionCommands == "" || isNaN(injectionCommands)) {injectionCommands = "0";}

  // Create injection config object containing all injection parameters
  var injectionConfig = {"Type": injectionType, "IP": injectionIP, "Timeout": injectionTimeout, "Port": injectionPort, "Onu": injectionOnu, "Tid": injectionTid, "Instance": injectionInstance, "Class": injectionClass, "Commands": injectionCommands, "Attributes": injectionAttributes, "Message": injectionMessage};
  console.log(injectionConfig)

  // Send the injection request with the config object
  var request = {"method": "PUT", "headers": {"Content-Type": "application/json"}, "body": JSON.stringify(injectionConfig)};
  fetch("/messages/inject", request)
  .then(response => response.text())
  .then(value => {console.log(value); document.getElementById("injectionResult").innerText = value;})
}

let ascending = true;

// Toggles ascending/descending order of message accordions
function toggleOrder()
{
  // Toggle order ascending/descending
  ascending = !ascending;
  if (ascending) {document.getElementById("buttonOrder").innerHTML = "&uarr;"}
  else {document.getElementById("buttonOrder").innerHTML = "&darr;"}

  // Create new main accordion container
  var newMessages = messageAccordion.cloneNode(false);

  // Get children and reverse their order
  var children = Array.from(messageAccordion.children);
  children.reverse();

  // Append children to new accordion in new order
  for (let child of children) {
    newMessages.append(child);
  }

  // Replace old main accordion container with new one
  messageAccordion.parentNode.replaceChild(newMessages, messageAccordion);
  messageAccordion = newMessages;
}


document.getElementById("scanPcapButton").addEventListener("click", function(e) {
  var select = document.getElementById("selectPCAP");

  var request = {"method": "GET", "headers": {"Content-Type": "application/json"}}; 

    fetch("/messages/showfiles", request)
    .then((response) => response.json())
    .then((json) =>{
      if ("FileList" in json){
        select.innerHTML = "";
        json["FileList"].forEach(function(file) {
          var option = document.createElement("option");
          option.value = file;
          option.text = file;
          select.appendChild(option);
        });
      }
    });
  
});
