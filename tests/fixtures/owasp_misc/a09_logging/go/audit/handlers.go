package audit

import (
	"log"
	"net/http"
)

func LoginFailedLegacy(w http.ResponseWriter, r *http.Request) {
	// codit-expect: CWE-117 form value logged with %s (CR/LF pass through unescaped)
	log.Printf("login failed for user %s", r.FormValue("user"))
	http.Error(w, "invalid credentials", http.StatusUnauthorized)
}



func LoginFailed(w http.ResponseWriter, r *http.Request) {
	// codit-safe: CWE-117 %q quotes the value and escapes control characters
	log.Printf("login failed for user %q", r.FormValue("user"))
	http.Error(w, "invalid credentials", http.StatusUnauthorized)
}
