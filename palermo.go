package palermo

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/go-toschool/palermo/auth"
)

// Session represents a user information returned by UserService
type Session struct {
	ID     string `json:"id,omitempty"`
	UserID string `json:"user_id,omitempty"`
	Email  string `json:"email,omitempty"`
	Token  string `json:"token,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// SessionCredentials represents credentials of an user session.
type SessionCredentials struct {
	ValidationToken string
	AuthToken       string
}

// SessionService manages user session and credentials. It provides methods
// to validate and refresh credentials.
// This interface allow the implementation of sessions using a data-store or in
// a stateless manner.
type SessionService interface {
	// UserSession validates and returns the associated session with the given
	// credentials.
	Session(s *SessionCredentials) (*Session, error)

	// RefreshSession validates and returns the associated session with the
	// given credentials. This method must  contain the logic to refresh a
	// session, which are implementation details.
	RefreshSession(s *SessionCredentials) (*Session, error)

	// Session creates credentials for the given session.
	CreateSession(s *Session) (*SessionCredentials, error)

	// Session creates credentials for the given session.
	UpdateSession(s *Session) (*SessionCredentials, error)
}

// NewSession creates a new user session.
func NewSession(u *auth.User, token string) (*Session, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	iat := time.Now()
	id := base64.StdEncoding.EncodeToString(b)

	return &Session{
		ID:        id,
		UserID:    u.UserId,
		Email:     u.Email,
		Token:     token,
		CreatedAt: iat,
		UpdatedAt: iat,
	}, nil
}
