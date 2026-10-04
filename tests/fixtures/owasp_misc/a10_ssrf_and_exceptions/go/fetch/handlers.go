package fetch

import (
	"database/sql"
	"io"
	"log"
	"net/http"
	"net/url"
)

var allowedHosts = map[string]bool{"status.acme.example": true, "api.github.com": true}

type Server struct {
	DB *sql.DB
}

func (s *Server) PreviewLegacy(w http.ResponseWriter, r *http.Request) {
	// codit-expect: CWE-918 http.Get on a URL from the query string
	resp, err := http.Get(r.URL.Query().Get("url"))
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(w, resp.Body)
}



func (s *Server) Preview(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil || u.Scheme != "https" || !allowedHosts[u.Hostname()] {
		http.Error(w, "host not allowed", http.StatusBadRequest)
		return
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// codit-safe: CWE-918 scheme and host allow-listed, redirects not followed
	resp, err := client.Get(u.String())
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(w, resp.Body)
}



func (s *Server) InvoiceLegacy(w http.ResponseWriter, r *http.Request) {
	var total int64
	err := s.DB.QueryRowContext(r.Context(), "SELECT total FROM invoices WHERE id = $1", r.URL.Query().Get("id")).Scan(&total)
	if err != nil {
		// codit-expect: CWE-209 raw database error text returned to the client
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte("ok"))
}



func (s *Server) Invoice(w http.ResponseWriter, r *http.Request) {
	var total int64
	err := s.DB.QueryRowContext(r.Context(), "SELECT total FROM invoices WHERE id = $1", r.URL.Query().Get("id")).Scan(&total)
	if err != nil {
		log.Printf("invoice lookup failed: %v", err)
		// codit-safe: CWE-209 generic message, details only in the server log
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte("ok"))
}
