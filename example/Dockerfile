FROM ubuntu 
RUN apt-get update && apt-get install -y ca-certificates
COPY example /bin/example
COPY templates /var/example/
ENTRYPOINT ["example", "-templates-dir", "/var/example/"]
