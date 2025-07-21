# Go Blockchain Service

🧱 This is a minimal and extendable blockchain service written in Go with the following features:

- 🧩 Modular architecture
- 🔐 JWT Authentication
- 🔄 P2P network
- ⛓ Blockchain with PoW consensus
- 🗄 PostgreSQL persistence
- 🔐 AES-GCM encryption
- 🚀 REST API (with Swagger)
- 📦 Dockerized (Go + KrakenD + Postgres)

## 🚀 Getting Started

### Prerequisites

- Docker
- Go >= 1.21 (for development)

### Setup

```bash
docker-compose up --build
```

Service runs on: `http://localhost:8080`

## 🛠 API

See Swagger docs at: `http://localhost:8080/swagger/index.html`

## 📂 Project Structure

- `cmd/blockchain/` — app entrypoint
- `internal/blockchain/` — blockchain logic
- `internal/api/` — HTTP handlers and routes
- `internal/p2p/` — peer-to-peer network
- `internal/consensus/` — PoW or PoS consensus
- `internal/crypto/` — encryption utils
- `internal/datastore/` — PostgreSQL interaction
- `internal/auth/` — JWT middleware
- `pkg/shared/` — shared data structures

## 🔒 Auth

Use `/auth/login` to get a JWT token and access protected routes.

## 📄 License

MIT
