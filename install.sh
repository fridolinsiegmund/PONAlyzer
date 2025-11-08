#!/bin/bash

GO_VERSION=1.25.2

echo "Installing APT packets ..."
sudo apt update
sudo apt install -y build-essential libpcap-dev

echo "Installing local GoLang $GO_VERSION ..."

chmod +x govenv.sh
chmod +x run.sh

# do not download again if file exists
if [ ! -f "go$GO_VERSION.linux-amd64.tar.gz" ]; then
    wget https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz
fi


tar -xzf go$GO_VERSION.linux-amd64.tar.gz

source ./govenv.sh

cd src
../go/bin/go mod tidy
cd ..

echo "Finished installation of PONAlyzer"
