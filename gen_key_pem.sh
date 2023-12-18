#!/bin/bash

# Generate private key
openssl genrsa -out privatekey.pem 2048

# Generate public key from private key
openssl rsa -in privatekey.pem -out publickey.pem -pubout -outform PEM