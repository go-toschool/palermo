package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/go-toschool/palermo"
	"github.com/go-toschool/palermo/auth"
	"github.com/go-toschool/palermo/jwt"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	_ "github.com/lib/pq"
)

const (
	authSecretKey       = "palermoAuthSecretKey"
	authTokenMaxAge     = 25 * time.Minute
	authTokenCookieName = "access_token"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetFormatter(&logrus.JSONFormatter{
		PrettyPrint: true,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "severity",
			logrus.FieldKeyMsg:   "message",
		},
		TimestampFormat: time.RFC3339Nano,
	})
	logrus.SetOutput(os.Stdout)
}

func main() {
	port := flag.Int64("port", 8003, "listening port")

	flag.Parse()

	srv := grpc.NewServer()

	sessSvc := &jwt.SessionService{
		SecretKey: []byte(authSecretKey),
		MaxAge:    authTokenMaxAge,
	}

	auth.RegisterAuthServiceServer(srv, &AuthService{
		SessionService: sessSvc,
	})

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Println("Starting palermo service...")
	log.Println(fmt.Sprintf("Palermo service, Listening on: %d", *port))
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

// AuthService ...
type AuthService struct {
	SessionService palermo.SessionService
}

// Get ...
func (as *AuthService) Get(ctx context.Context, gr *auth.GetRequest) (*auth.GetResponse, error) {
	logrus.Info("AuthService: Method Get")
	s, err := as.SessionService.Session(&palermo.SessionCredentials{
		ValidationToken: gr.Data.ValidationToken,
		AuthToken:       gr.Data.AuthToken,
	})
	if err != nil {
		return nil, err
	}

	return &auth.GetResponse{
		Data: &auth.Session{
			Id:        s.ID,
			UserId:    s.UserID,
			Email:     s.Email,
			Token:     s.Token,
			CreatedAt: s.CreatedAt.Unix(),
			UpdatedAt: s.UpdatedAt.Unix(),
		},
	}, nil
}

// Create ...
func (as *AuthService) Create(ctx context.Context, gr *auth.CreateRequest) (*auth.CreateResponse, error) {
	logrus.Info("AuthService: Method Create")
	ss, err := as.SessionService.CreateSession(&palermo.Session{
		ID:        gr.Data.Id,
		UserID:    gr.Data.UserId,
		Email:     gr.Data.Email,
		Token:     gr.Data.Token,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	if err != nil {
		return nil, err
	}

	return &auth.CreateResponse{
		Data: &auth.SessionCredentials{
			ValidationToken: ss.ValidationToken,
			AuthToken:       ss.AuthToken,
		},
	}, nil
}

// Update ...
func (as *AuthService) Update(ctx context.Context, gr *auth.UpdateRequest) (*auth.UpdateResponse, error) {
	logrus.Info("AuthService: Method Update")
	s, err := as.SessionService.RefreshSession(&palermo.SessionCredentials{
		ValidationToken: gr.Data.ValidationToken,
		AuthToken:       gr.Data.AuthToken,
	})
	if err != nil {
		return nil, err
	}

	return &auth.UpdateResponse{
		Data: &auth.Session{
			Id:        s.ID,
			UserId:    s.UserID,
			Email:     s.Email,
			Token:     s.Token,
			CreatedAt: s.CreatedAt.Unix(),
			UpdatedAt: s.UpdatedAt.Unix(),
		},
	}, nil
}

// Delete ...
func (as *AuthService) Delete(ctx context.Context, gr *auth.DeleteRequest) (*auth.DeleteResponse, error) {
	logrus.Info("AuthService: Method Delete")
	return nil, nil
}
