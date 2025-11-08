## PONAlyzer
PONAlyzer is a tool for monitoring, analysis, and injection of OMCI messages in VOLTHA-based SD-PONs.

## Installation
For installation on Linux (Ubuntu) just run the install script. This installs a local GoLang environment for PONAlyzer without interfering the systems Go installation or packages.
```
./install.sh
```

## Usage
### Launching the Web Server
Run the following command to launch the web server:

```
(sudo) ./run.sh
```

Using the sniffing utility requires permissions to the network interface.

### Accessing the Web-GUI
After the web server is launched, the WebGUI can be reached by visiting the server machine's IP on port 8080 using a web browser:

http://ServerIP:8080/

Alternatively, if you're running a local instance of the web server, you can access it via the localhost:

http://localhost:8080/

On visit, the web server will serve all dependencies required for the Web-GUI, including [Bootstrap](https://getbootstrap.com/) v5.3.3 dependencies and the `script.js`.

### Importing/Exporting PCAP Files
When exporting PCAP files, they will be exported to the `/pcaps/` directory by default.

PCAP files will be imported from the same directory by default.
