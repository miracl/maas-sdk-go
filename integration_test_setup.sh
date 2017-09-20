#!/bin/bash

cd example

GOOS=linux GOARCH=amd64 go build -o example

docker build -t miracl/maas-sdk-go-example .
docker-compose up -d
RC=$(docker-compose ps | grep -c "Exit 1")

if [ $RC -eq 0 ]
then
    exit 0
else
    exit 1
fi