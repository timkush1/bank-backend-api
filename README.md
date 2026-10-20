# Bank Backend API

A bank REST API in Go with JWT authentication, role-based access control (user / admin), and structured JSON access logging. It started from an insecure baseline, which I hardened.

## Features

- **Authentication**: register and log in. Passwords are hashed with **bcrypt**, and JWTs are signed with HS256 and expire.
- **Role-based access control**: admins manage accounts. Users can only read or change their own balance, and admins can read any balance.
- **Input validation**: duplicate usernames are rejected, and withdrawals check the balance first.
- **Access logging**: every request and response is written to `access.log` as one JSON line (URL, query params, headers, body sizes and status class). Request bodies are never logged, so passwords stay out of the logs. These logs are the input for [Bola-detector](https://github.com/timkush1/Bola-detector).

## Security improvements over the baseline

| Issue | Fix |
|-------|-----|
| Passwords stored in plain text | Hashed with bcrypt |
| Duplicate usernames allowed | Rejected at `/register` |
| Tokens never expired | JWTs carry an expiry |
| No authorization checks | `Auth` and `RoleMiddleware` middleware check the token and role on protected routes |

## Tech stack

Go (`net/http`) · `golang-jwt` (dgrijalva/jwt-go) · `golang.org/x/crypto/bcrypt` · OpenAPI 3 spec (`openapi.yaml`)

## Project structure

```
main.go        Server setup and routing
pkg/api.go     Handlers: register, login, accounts, balance
pkg/utils.go   Auth/role middleware and access logging
pkg/models.go  Data models (in-memory storage)
openapi.yaml   API specification
```

## Getting started

```bash
export JWT_SECRET=$(openssl rand -hex 32)   # required
go run .                                    # listens on :8080
```

Data is kept in memory, so it resets when the server restarts.

## API

| Method | Endpoint | Access | Description |
|--------|----------|--------|-------------|
| POST | `/register` | Public | Create a user (`username`, `password`, `role`) |
| POST | `/login` | Public | Returns a JWT |
| POST | `/accounts` | Admin | Create an account for a user |
| GET | `/accounts` | Admin | List all accounts |
| GET | `/balance?user_id=<id>` | Owner or admin | Get a balance |
| POST | `/balance` | Owner | Deposit (`user_id`, `amount`) |
| DELETE | `/balance` | Owner | Withdraw (`user_id`, `amount`) |

Send `Authorization: Bearer <token>` on every protected route. The full spec is in [`openapi.yaml`](openapi.yaml).

### Example

```bash
H='Content-Type: application/json'

curl -X POST localhost:8080/register -H "$H" -d '{"username":"admin","password":"admin123","role":"admin"}'
curl -X POST localhost:8080/register -H "$H" -d '{"username":"user1","password":"password123","role":"user"}'

ADMIN=$(curl -s -X POST localhost:8080/login -H "$H" -d '{"username":"admin","password":"admin123"}' | jq -r .token)
USER=$(curl -s -X POST localhost:8080/login -H "$H" -d '{"username":"user1","password":"password123"}' | jq -r .token)

# Admin creates an account for user 2 (user1)
curl -X POST localhost:8080/accounts -H "Authorization: Bearer $ADMIN" -H "$H" -d '{"type":"checking","balance":500,"userID":2}'

# user1 checks, deposits and withdraws
curl "localhost:8080/balance?user_id=2" -H "Authorization: Bearer $USER"
curl -X POST   localhost:8080/balance -H "Authorization: Bearer $USER" -H "$H" -d '{"user_id":2,"amount":50}'
curl -X DELETE localhost:8080/balance -H "Authorization: Bearer $USER" -H "$H" -d '{"user_id":2,"amount":30}'
```
