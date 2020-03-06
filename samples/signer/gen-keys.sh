#!/bin/bash
#Generate an elliptical curve p256 key pair

openssl ecparam -genkey -name prime256v1 -noout -out ec256.priv
openssl ec -in ec256.priv  -pubout -out ec256.pub


