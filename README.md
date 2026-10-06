# test-gov-frontend

Frontend application for Keycloak SSO, 2FA (Google Authenticator) onboarding, and JWT/JWKS verification gateway (Alem BFF).

## Features
- Keycloak OpenID Connect (OIDC) integration
- Direct Login via Alem BFF Gateway (`POST /api/auth/login`)
- 2FA (TOTP / Google Authenticator) first-login setup with QR code
- JWT Token Inspector (Access Token, Refresh Token, ID Token)
- Public JWKS signature verification (`POST /api/auth/verify-id-token`)
- User Registration (`POST /api/auth/register`)

## Development
```bash
npm install
npm run dev
```

## Production Build
```bash
npm run build
npm run preview
```
