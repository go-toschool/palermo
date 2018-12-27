VERSION=v0.0.1
SVC=palermo
PROTO_SVC=auth
BIN=$(PWD)/bin/$(SVC)

GO ?= go
LDFLAGS='-extldflags "static" -X main.svcVersion=$(VERSION) -X main.svcName=$(SVC)'
TAGS=netgo -installsuffix netgo

REGISTRY_URL=gotoschool
proto p:
	@echo "[proto] Generating golang proto..."
	@rm $(PROTO_SVC)/$(PROTO_SVC).pb.go
	@protoc  -I $(PROTO_SVC)/ $(PROTO_SVC)/$(PROTO_SVC).proto --go_out=plugins=grpc:$(PROTO_SVC)

run r: proto
	@echo "[running] Running service..."
	@go run cmd/server/main.go

build b:
	@echo "[build] Building service..."
	@cd cmd/server && $(GO) build -o $(BIN) -ldflags=$(LDFLAGS) -tags $(TAGS)


linux l: proto
	@echo "[build] Building for linux..."
	@cd cmd/server && GOOS=linux $(GO) build -a -o $(BIN) --ldflags $(LDFLAGS) -tags $(TAGS)

docker d: linux
	@echo "[docker] Building image..."
	@docker build -t $(REGISTRY_URL)/$(SVC):$(VERSION) .

push: docker
	@echo "[docker] pushing $(REGISTRY_URL)/$(SVC):$(VERSION)"
	docker push $(REGISTRY_URL)/$(SVC):$(VERSION)