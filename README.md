# jwt-generator
Tool for simple generating JWTokens

1. Install by composer require monderka/jwt-generator
2. Generate key pairs for example (available algos are EdDSA, ES256, ES384, ES512, HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384)
```
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
```
