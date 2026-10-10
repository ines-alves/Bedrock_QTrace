module example.invalid/svc

go 1.24

require golang.org/x/crypto v0.31.0

require (
	github.com/cloudflare/circl v1.5.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/spf13/cobra v1.8.0
)

replace golang.org/x/crypto => ../crypto-fork
replace github.com/spf13/cobra => ../cobra
