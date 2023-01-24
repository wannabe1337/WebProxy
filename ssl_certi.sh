#!/bin/sh

#Create certs directory
mkdir certs

#Create the Root CA
openssl genrsa -out ./certs/rootCA.key 4096
openssl req -x509 -new -nodes -key ./certs/rootCA.key -sha256 -days 5000 -out ./certs/rootCA.pem


# apt install curl mk-ca-bundle
curl https://curl.se/ca/cacert.pem >> ./certs/ca-bundle.pem


# # Install the rootCA Cert as a trusted root CA on Ubuntu
# sudo cp ./certs/rootCA.pem /usr/local/share/ca-certificates/rootCA.crt

