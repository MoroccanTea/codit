package store

import (
	"context"
	"database/sql"
	"time"
)

type User struct {
	ID           int64     `json:"id" db:"id"`
	Email        string    `json:"email" db:"email"`
	DisplayName  string    `json:"display_name" db:"display_name"`
	PasswordHash string    `json:"-" db:"password_hash"`
	TOTPEnabled  bool      `json:"totp_enabled" db:"totp_enabled"`
	TOTPSecret   string    `json:"totp_secret,omitempty" db:"totp_secret"`
	IsAdmin      bool      `json:"is_admin" db:"is_admin"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type UserStore struct {
	DB *sql.DB
}

func (s *UserStore) ByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, email, display_name, password_hash, totp_enabled, totp_secret, is_admin FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.DisplayName, &u.PasswordHash, &u.TOTPEnabled, &u.TOTPSecret, &u.IsAdmin)
	return u, err
}

func (s *UserStore) ByID(ctx context.Context, id int64) (*User, error) {
	u := &User{}
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, email, display_name, password_hash, totp_enabled, totp_secret, is_admin FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.DisplayName, &u.PasswordHash, &u.TOTPEnabled, &u.TOTPSecret, &u.IsAdmin)
	return u, err
}

func (s *UserStore) Save(ctx context.Context, u *User) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE users SET email = $1, display_name = $2, totp_enabled = $3, totp_secret = $4, is_admin = $5 WHERE id = $6`,
		u.Email, u.DisplayName, u.TOTPEnabled, u.TOTPSecret, u.IsAdmin, u.ID)
	return err
}

func (s *UserStore) Create(ctx context.Context, email string, hash []byte) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO users (email, password_hash) VALUES ($1, $2)`, email, string(hash))
	return err
}

func (s *UserStore) SaveEmailCode(ctx context.Context, id int64, codeHash string, expires time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET email_code = $1, email_code_expires = $2 WHERE id = $3`, codeHash, expires, id)
	return err
}

func (s *UserStore) FailedOTPAttempts(ctx context.Context, id int64) int {
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT otp_failed_attempts FROM users WHERE id = $1`, id).Scan(&n)
	return n
}

func (s *UserStore) IncrementFailedOTP(ctx context.Context, id int64) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE users SET otp_failed_attempts = otp_failed_attempts + 1 WHERE id = $1`, id)
}

func (s *UserStore) ResetFailedOTP(ctx context.Context, id int64) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE users SET otp_failed_attempts = 0 WHERE id = $1`, id)
}
