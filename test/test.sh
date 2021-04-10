#!/bin/bash

# Build
go build ../cmd/listener.go
go build ../cmd/poller.go

# Setup test files
echo "This is a test configuration file of some kind. It has an IP address in it: 1.2.3.4. The IP will be replaced." > ./config.txt
echo "1.2.3.4" > ./ip.txt
echo "Creating EC key pair"
openssl ecparam -name secp521r1 -genkey -noout -out privtest.pem && openssl ec -in privtest.pem -pubout -out pubtest.pem

printf "\nInitial IP:\n"
cat ./ip.txt

printf "\nInitial config:\n"
cat ./config.txt

echo "Starting listener:"
./listener ./ip.txt ../scripts/update-ip.sh ./pubtest.pem 127.0.0.1:8580 &
sleep 1

echo "Running poller:"
./poller ./privtest.pem "http://127.0.0.1:8580/ping"
sleep 1

echo "Killing listener"
kill $!

printf "\nShould contain 127.0.0.1:\n"
cat ./ip.txt
printf "\nShould contain 127.0.0.1:\n"
cat ./config.txt

# Cleaning up
rm ./config.txt
rm ./ip.txt
rm ./poller
rm ./listener
rm ./privtest.pem
rm ./pubtest.pem

