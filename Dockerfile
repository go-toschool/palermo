FROM alpine

RUN apk add --update ca-certificates

COPY bin/palermo /usr/bin/palermo

EXPOSE 8003

ENTRYPOINT palermo