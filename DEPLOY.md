# Production deployment with Docker Compose

This is a single-node deployment of the HTTP control plane. It uses the
operator-managed PostgreSQL, Valkey, NATS, and Ciphera services already
configured for the application; Compose does not create replacement databases
or enable provisioning mutations by default. It is not a high-availability or
blue-green deployment.

## Prepare the host

1. Install Docker Engine and the Compose plugin. Use a dedicated host and Docker
   identity for this service. The container runs as UID/GID `10001`, drops all
   Linux capabilities, and has a read-only root filesystem.
2. Check out the approved release and prepare protected host directories:

   ```sh
   sudo install -d -o 10001 -g 10001 -m 0700 /srv/shared-resource-provisioner/data
   sudo install -d -o 10001 -g 10001 -m 0700 /srv/shared-resource-provisioner/config
   sudo install -d -o 10001 -g 10001 -m 0700 /srv/shared-resource-provisioner/secrets
   ```

   Restrict access to the host directories to the service operator as well as
   UID/GID `10001` where needed for container reads. Place the TLS certificate
   and private key at `config/tls/tls.crt` and `config/tls/tls.key`; the private
   key must be readable by UID `10001` and not by unrelated host users.
3. Populate `config/policy.json`, `config/targets.json`, and
   `config/ciphera.json` using the documented example formats. Referenced
   endpoint and Ciphera service-key files must be placed under `secrets/` with
   the exact filenames used by those JSON files (the examples use `/run/secrets/`).
   Keep credentials out of the repository, image, `.env.production`, and logs.
4. Create `.env.production` from `.env.production.example` and set the public
   HTTPS MCP URL, OIDC issuer/audience, exact administrator subject JSON array,
   and host paths. Keep this file out of version control. Leave
   `SRP_MUTATIONS_ENABLED=false` until the production release gate and recovery
   checks in `docs/runbooks/deployment-hardening.md` are complete.

The data directory must be owned by UID/GID `10001` and mode `0700`; the
application creates the SQLite database with mode `0600`. Do not mount an
ephemeral container path for this data.

## Start and update

From the release checkout:

```sh
docker compose --env-file .env.production -f compose.production.yaml up -d --build
```

The service binds TLS on container port `8443` and publishes it only on host
loopback by default (`127.0.0.1:8443`). Configure the host reverse proxy to
forward the intended MCP and administration routes to that listener, or adjust
the host port binding only as part of an explicit network/security review. The
certificate mounted in `config/tls/` must be valid for the configured public
MCP URL. Restrict the admin REST API at the proxy/network layer as well.

Check container state with `docker compose --env-file .env.production -f
compose.production.yaml ps` and verify `GET /healthz` through the intended
network path. `/healthz` confirms process liveness only; it does not prove
SQLite, OIDC, Ciphera, or target readiness. Logs are JSON diagnostics; protect
them and do not enable request/credential logging.

To update, deploy an approved immutable release, then run the same `up -d
--build` command from its checkout. Preserve the previous release and a verified
SQLite backup until the new instance is confirmed. Database rollback, target
state, and secret-store recovery require their own procedures.

## Backup and shutdown

Use the provisioner's `backup` subcommand to create a consistent SQLite backup,
then transfer an encrypted copy off-host using the approved backup system. See
the [host-loss recovery drill](docs/runbooks/host-loss-recovery.md). Compose
allows 75 seconds for graceful shutdown, exceeding the application's 60-second
request-drain deadline.

Do not enable mutation operations until the configured target limits, Ciphera
identity, backup/restore drill, TLS/OIDC, monitoring, and operator security
review have passed for this environment. See the [deployment hardening
checklist](docs/runbooks/deployment-hardening.md).
