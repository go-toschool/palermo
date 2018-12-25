// Package jwt implements palermo.SessionService using JWT tokens.
//
//  - Validation Token keys:
//   * standard: jti, iat, sub, exp, iss
//  - Authentication Token kys:
//   * standard: jti, iat, sub, exp, iss
//   * custom: id, email, host, created_at, updated_at
package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-toschool/palermo"
)

const tokenIDnumBytes = 32

type sessionClaims struct {
	jwt.StandardClaims

	// Custom claims used to store user session.
	ID        string `json:"id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	Token     string `json:"-"`
	Email     string `json:"email,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

func (sc *sessionClaims) Session() *palermo.Session {
	return &palermo.Session{
		ID:        sc.ID,
		Email:     sc.Email,
		UserID:    sc.UserID,
		Token:     sc.Token,
		CreatedAt: time.Unix(sc.CreatedAt, 0),
		UpdatedAt: time.Unix(sc.UpdatedAt, 0),
	}
}

// SessionService implements palermo.SessionService using JWT tokens.
type SessionService struct {
	SecretKey []byte
	MaxAge    time.Duration
}

// Session validates and returns the user session associated with the given
// credentials.
func (uss *SessionService) Session(c *palermo.SessionCredentials) (*palermo.Session, error) {
	authClaims, valClaims, err := uss.parseTokens(c.AuthToken, c.ValidationToken)
	if err != nil {
		return nil, err
	}

	if err := uss.validateClaims(valClaims, authClaims); err != nil {
		return nil, err
	}

	return authClaims.Session(), nil
}

// RefreshSession validates and returns the user session associated with the
// given credentials. This method skips the validation of the expiry of the
// tokens.
// Also the associated user session is returned updated.
func (uss *SessionService) RefreshSession(c *palermo.SessionCredentials) (*palermo.Session, error) {
	authClaims, valClaims, err := uss.parseTokens(c.AuthToken, c.ValidationToken)
	if err != nil {
		if !isTokenExpired(err) {
			return nil, err
		}
	}

	if err := uss.validateClaims(valClaims, authClaims); err != nil {
		return nil, err
	}

	s := authClaims.Session()
	s.UpdatedAt = time.Now()
	return s, nil
}

// CreateSession creates new credentials for the given session.
func (uss *SessionService) CreateSession(us *palermo.Session) (*palermo.SessionCredentials, error) {
	return uss.sessionCredentials(us)
}

// UpdateSession creates new credentials for the given session.
func (uss *SessionService) UpdateSession(us *palermo.Session) (*palermo.SessionCredentials, error) {
	return uss.sessionCredentials(us)
}

func (uss *SessionService) sessionCredentials(us *palermo.Session) (*palermo.SessionCredentials, error) {
	id, err := generateRandomToken(tokenIDnumBytes)
	if err != nil {
		return nil, err
	}

	iat := time.Now()
	exp := iat.Add(uss.MaxAge)

	validationToken, err := uss.tokenString(&sessionClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        id,
			Issuer:    us.Token,
			Subject:   us.Email,
			IssuedAt:  iat.Unix(),
			ExpiresAt: exp.Unix(),
		},
	})
	if err != nil {
		return nil, err
	}

	authToken, err := uss.tokenString(&sessionClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        id,
			Issuer:    us.Token,
			Subject:   us.Email,
			IssuedAt:  iat.Unix(),
			ExpiresAt: exp.Unix(),
		},
		ID:        us.ID,
		UserID:    us.UserID,
		Email:     us.Email,
		Token:     us.Token,
		CreatedAt: us.CreatedAt.Unix(),
		UpdatedAt: us.UpdatedAt.Unix(),
	})
	if err != nil {
		return nil, err
	}

	return &palermo.SessionCredentials{
		ValidationToken: validationToken,
		AuthToken:       authToken,
	}, nil
}

func (uss *SessionService) validateClaims(lhs, rhs *sessionClaims) error {
	if lhs.Id != rhs.Id {
		return errors.New("jwt: validation and authentication token jti mismatched")
	}

	if lhs.IssuedAt != rhs.IssuedAt {
		return errors.New("jwt: validation and authentication token iat mismatched")
	}

	if lhs.ExpiresAt != rhs.ExpiresAt {
		return errors.New("jwt: validation and authentication token exp mismatched")
	}

	if lhs.Subject != rhs.Subject {
		return errors.New("jwt: validation and authentication token sub mismatched")
	}

	if lhs.Issuer != rhs.Issuer {
		return errors.New("jwt: validation and authentication token iss mismatched")
	}

	return nil
}

func (uss *SessionService) parseTokens(authToken, valToken string) (*sessionClaims, *sessionClaims, error) {
	authClaims, authErr := uss.tokenClaims(authToken)
	valClaims, valErr := uss.tokenClaims(valToken)

	var err error
	if authErr != nil {
		err = authErr
	}
	if err == nil && valErr != nil {
		err = valErr
	}

	return authClaims, valClaims, err
}

func (uss *SessionService) tokenClaims(tokenStr string) (*sessionClaims, error) {
	var claims = new(sessionClaims)
	token, err := jwt.ParseWithClaims(tokenStr, claims, uss.verifySigningMethod)

	if c, ok := token.Claims.(*sessionClaims); ok {
		claims = c
	}

	return claims, err
}

func (uss *SessionService) tokenString(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(uss.SecretKey)
}

func (uss *SessionService) verifySigningMethod(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return uss.SecretKey, nil
}

func generateRandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func isTokenExpired(err error) bool {
	e, ok := err.(*jwt.ValidationError)
	if !ok {
		return false
	}
	return (e.Errors & ^jwt.ValidationErrorExpired) == 0
}
