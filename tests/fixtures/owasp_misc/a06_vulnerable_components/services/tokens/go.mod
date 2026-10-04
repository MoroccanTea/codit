module github.com/acme/tokens

go 1.23

require (
	// codit-expect: CWE-1104 dgrijalva/jwt-go is unmaintained (audience bypass CVE-2020-26160)
	github.com/dgrijalva/jwt-go v3.2.0+incompatible



	// codit-safe: CWE-1104 maintained fork, current release
	github.com/golang-jwt/jwt/v5 v5.2.1
)
