# SMTP Relay Manager

An authenticated SMTP relay with domain-scoped administration and a static management UI.

## Architecture

- `nginx` serves the SvelteKit CSR build and proxies `/api/v1` to FastAPI.
- `backend` and `smtp` run different commands from the same Python image.
- `smtp` exposes port 465 (implicit TLS) and port 587 (required STARTTLS).
- MySQL stores identities, grants, encrypted upstream credentials, and delivery metadata.
- Your existing HTTP reverse proxy terminates web HTTPS. SMTP terminates TLS itself.

Applications authenticate using the generated credential ID as the SMTP username and the generated token as the password. Each token is restricted to addresses or domains already granted to its owner. SMTP sending permissions are separate from domain management roles.

## Deployment

Requirements: Docker with Compose, an HTTPS reverse proxy, and an SMTP TLS certificate matching the hostname applications use.

1. Copy `.env.example` to `.env` and replace both database passwords. Update `DATABASE_URL` with the same application password, URL-encoding special characters.
2. Generate `ENCRYPTION_KEY` with `openssl rand -base64 32 | tr -- '+/' '-_'`. Keep this key outside source control and back it up separately from MySQL. Losing it makes stored upstream passwords unreadable.
3. Set `PUBLIC_BASE_URL` to the management UI's HTTPS origin, without a path. Set `SMTP_HOSTNAME`, for example `smtp-relay.ory.kr`.
4. Set `SMTP_CERT_DIR` to the host certificate directory. It is mounted read-only at `/app/cert`; the directory must contain `fullchain.pem` and `privkey.pem`.
5. Allow container UID/GID `10001:10001` to traverse the certificate directory and read both files. Do not make the private key world-readable. Renewals must retain these permissions.
6. Configure your HTTPS proxy to forward to the Nginx HTTP endpoint (default `127.0.0.1:8080`). Set `TRUSTED_PROXY_CIDRS` to the actual proxy hops, including Nginx's Docker network when forwarding client IPs. Never trust all addresses. Keep the HTTP endpoint accessible only to that proxy.

Build and start:

```sh
docker compose up --build -d
docker compose run --rm backend python -m smtp_relay_manager.cli create-operator admin
```

The CLI prompts for the operator password. Database migrations run once before the services start. Neither the API nor MySQL publishes a host port. The SMTP container runs as a non-root user, mapping external 465/587 to internal 8465/8587.

The operator creates users and copies one-time invitation links for delivery through an existing channel. Users set their own passwords, request domain registration, and wait for operator approval. Domain owners configure one upstream SMTP server and appoint domain administrators. Administrators register sender addresses and assign exact addresses or the entire domain (`*`) to existing users.

### External MySQL

In `.env`, use:

```dotenv
COMPOSE_FILE=compose.yaml
DATABASE_URL=mysql+asyncmy://relay:encoded-password@db.example.com:3306/relay
```

This runs the application without the bundled MySQL container. Provision an empty database and a user permitted to apply the migrations. Keep external database traffic on a trusted network or an encrypted database connection. Other database engines are not supported.

### Certificate renewal

The SMTP service checks the mounted files every 30 seconds. It validates the hostname, dates, and matching private key before switching new handshakes to the new certificate. Existing connections keep their current context. Invalid replacements leave the last valid context active; expired certificates reject new TLS handshakes.

Mount a directory rather than individual files so atomic renewal replacements are visible. If the certificate files are symlinks, their targets must also be accessible inside the container. A dedicated directory containing the complete pair avoids exposing unrelated certificates. Certificate issuance and renewal are performed by your existing infrastructure.

## Security and delivery behavior

- Management authentication uses an HttpOnly, Secure session cookie, Origin checking, and CSRF protection. Default session duration is 12 hours; invitation links expire after 24 hours.
- Domain owners can configure upstream SMTP and manage administrators. Administrators manage sender grants. Being an operator does not automatically grant domain configuration or sending privileges.
- SMTP AUTH PLAIN and LOGIN are permitted only over TLS. Tokens are shown once and stored as hashes. Revocations are checked again immediately before upstream DATA; an already authorized in-flight delivery may finish.
- Envelope MAIL FROM and a single header From must contain the same authorized address. SMTPUTF8, null senders, and quoted local parts are not supported in v1.
- Upstream connections allow public addresses only. All resolved addresses are checked and the connection is pinned to a validated address while retaining hostname verification. Password authentication requires TLS or STARTTLS; unauthenticated plaintext upstreams are supported.
- All upstream recipients must be accepted before DATA is sent. A recipient rejection cancels the whole submission before message content is transmitted.
- Success means the upstream accepted the message, not that it reached an inbox. There is no queue or automatic retry.
- A disconnect during DATA can make the result unknown. The client receives a temporary error and may retry, which can produce duplicates. Once upstream acceptance is known, a later log-write failure does not turn success into a retryable response.
- Only delivery metadata is stored. Message bodies, attachments, subjects, passwords, and raw SMTP conversations are not logged. Logs are retained for 30 days; incomplete attempts are classified as unknown after a crash.
- Operators see all delivery logs. Current domain owners see their domains' logs. Domain administrators and ordinary users see only their own submissions.

Default bounds: 25 MiB per message, 100 recipients, 32 SMTP connections, and 4 concurrent buffered DATA operations. Raw in-flight message payload is therefore bounded to 100 MiB at defaults, excluding protocol/library overhead. Configure `SMTP_MAX_MESSAGE_BYTES`, `SMTP_MAX_RECIPIENTS`, `SMTP_MAX_CONNECTIONS`, and `SMTP_MAX_DATA_CONNECTIONS` together with available container memory. Connection, command, and total delivery timeouts default to 15, 30, and 120 seconds.

SMTP stops accepting connections on SIGTERM and drains existing work. Compose allows 150 seconds before forced termination. If increasing `SMTP_IDLE_TIMEOUT` or `SMTP_TRANSACTION_TIMEOUT`, also increase `SMTP_STOP_GRACE_PERIOD` beyond the larger timeout plus a shutdown margin.

## Development and verification

Python dependencies are managed with `uv`; frontend dependencies use npm lockfiles.

```sh
cd backend
uv sync --python 3.12
uv run pytest
```

Database integration tests require `TEST_DATABASE_URL` pointing to a **disposable MySQL database**. The tests recreate tables. Never use an application or production database. Tests that require MySQL explicitly skip if the variable is absent.

```sh
cd frontend
npm ci
npm run check
npm run build
```

For local web development, keep an HTTPS origin so Secure cookies work; route `/api/v1` to FastAPI. Run migrations using `uv run alembic upgrade head`, the API using `uv run uvicorn smtp_relay_manager.main:app`, and SMTP using `uv run python -m smtp_relay_manager.smtp`. SMTP requires certificate files even in development.

## Operations

Inspect `docker compose ps` and `docker compose logs backend smtp` for health and sanitized operational failures. Back up the MySQL volume and the encryption key separately. Restore both before using encrypted upstream credentials. Migrations are serialized with a MySQL advisory lock. The backend performs expired-log and authentication-record maintenance periodically.

Authentication and authorization live behind separate Python module boundaries with stable internal user IDs. A later SSO integration must link external identities to those IDs to preserve existing domain grants and SMTP credentials. Replacing an identity provider must not bypass the shared sender policy.
