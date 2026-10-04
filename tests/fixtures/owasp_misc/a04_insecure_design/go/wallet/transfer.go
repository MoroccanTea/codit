package wallet

import (
	"encoding/json"
	"errors"
	"net/http"
)

type TransferRequest struct {
	ToAccount string `json:"to_account"`
	Amount    int64  `json:"amount_cents"`
}

type Service struct {
	Ledger Ledger
}

type Ledger interface {
	Balance(account string) (int64, error)
	Move(from, to string, cents int64) error
}

var ErrInvalidAmount = errors.New("invalid amount")

func (s *Service) TransferLegacy(w http.ResponseWriter, r *http.Request, from string) {
	var req TransferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	balance, _ := s.Ledger.Balance(from)
	// codit-expect: CWE-840 only the upper bound is checked; a negative amount pulls money from the recipient
	if req.Amount > balance {
		http.Error(w, "insufficient funds", http.StatusConflict)
		return
	}
	_ = s.Ledger.Move(from, req.ToAccount, req.Amount)
	w.WriteHeader(http.StatusNoContent)
}



func (s *Service) Transfer(w http.ResponseWriter, r *http.Request, from string) {
	var req TransferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	balance, err := s.Ledger.Balance(from)
	// codit-safe: CWE-840 amount must be positive and within the balance
	if err != nil || req.Amount <= 0 || req.Amount > balance || req.ToAccount == from {
		http.Error(w, ErrInvalidAmount.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := s.Ledger.Move(from, req.ToAccount, req.Amount); err != nil {
		http.Error(w, "transfer failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
