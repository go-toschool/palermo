SVC=auth

proto p:
	@echo "[proto] Generating golang proto..."
	@rm $(SVC)/$(SVC).pb.go
	@protoc  -I $(SVC)/ $(SVC)/$(SVC).proto --go_out=plugins=grpc:$(SVC)

run r: proto
	@echo "[running] Running service..."
	@go run cmd/server/main.go