#!/bin/bash

cd example

GOOS=linux GOARCH=amd64 go build -o example

docker build -t miracl/maas-sdk-go-example .
docker-compose up -d
RC=$(docker-compose ps | grep -c "Exit 1")

if [ $RC -ne 0 ]
then
    exit 1
fi

while ! curl http://localhost:8002 > /dev/null ; do
  sleep 1
done

cd ..
go test -integration -v

cd example
docker-compose down
rm example