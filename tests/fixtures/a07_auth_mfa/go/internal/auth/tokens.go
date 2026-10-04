package auth

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var signingKey = []byte(os.Getenv("JWT_SIGNING_KEY"))

const (
	PurposeSession    = "session"
	PurposeMFAPending = "2fa_pending"
)

type Claims struct {
	UserID  int64  `json:"uid"`
	Purpose string `json:"purpose"`
	MFA     bool   `json:"mfa"`
	jwt.RegisteredClaims
}

// IssueLegacySession is still used by the v1 mobile app.
func IssueLegacySession(userID int64) (string, error) {
	claims := Claims{
		UserID:  userID,
		Purpose: PurposeSession,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
			// codit-expect: CWE-613 access token valid for a whole year
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(365 * 24 * time.Hour)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(signingKey)
}

// IssueSession issues a full session once every required factor has been verified.
func IssueSession(userID int64, mfa bool) (string, error) {
	claims := Claims{
		UserID:  userID,
		Purpose: PurposeSession,
		MFA:     mfa,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
			// codit-safe: CWE-613 15-minute access token, refresh handled by a rotating server-side token
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(signingKey)
}

// IssueMFAPending issues a token that is only accepted by the /v2/login/2fa endpoint.
func IssueMFAPending(userID int64) (string, error) {
	claims := Claims{
		UserID:  userID,
		Purpose: PurposeMFAPending,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			Audience:  jwt.ClaimStrings{"login-2fa"},
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(signingKey)
}

func Parse(tokenString string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return signingKey, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}
