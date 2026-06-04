# Phase 2d CP4 — turning on MySQL TLS

This walkthrough turns the `mysql` container into a TLS-only listener
and points the FastAPI app + Celery worker at it with a mutually-
authenticated connection. It assumes Phase 2d CP4.1 (engine TLS
wiring) and CP4.2 (docker-compose mounts) have shipped — both are on
`main`.

There are two new cert kinds in play:

| Type            | EKU         | Who presents it    | Lifetime |
|-----------------|-------------|--------------------|----------|
| `mysql`         | serverAuth  | the mysqld daemon  | 30 days  |
| `mysql-client`  | clientAuth  | app + worker       | 30 days  |

Both come from the same Vault PKI (or `LocalDevPKI` in dev) that the
rest of the control plane already shares. The CA bundle the client
trusts is the same one the FastAPI listener carries.

## 1. Prerequisites

- The repo has been brought up at least once on this host (so
  `tls/mysql/` exists from the bind-mount).
- `wg-manager operators add` has been used to register at least one
  operator with the `admin` role.
- `make pki-bootstrap` (or `PKI_BACKEND=local`) has been run so a PKI
  backend is reachable.
- The database is currently up: `make db-up` works.

If the database is up but already has
`require_secure_transport=ON` enforced and you don't yet have a
client cert, skip ahead to
[§9 Bootstrap on a TLS-enforced DB](#9-bootstrap-on-a-tls-enforced-db).

## 2. Mint the server cert

```bash
make mysql-tls-issue
```

This writes three files into `tls/mysql/`:

- `server.crt` — the mysqld leaf cert (CN=localhost, SANs cover
  `localhost`, `127.0.0.1`, `mysql`, `wg_manager_mysql`).
- `server.key` — the matching private key (mode 0600).
- `ca.crt` — the CA chain mysqld advertises to clients.

The audit row lands in the `certificate` table with
`cert_type=mysql` and `operator_id=NULL`.

## 3. Mint the client cert (app + worker)

```bash
wg-manager certs issue --type mysql-client --cn wg-manager-app \
  --ttl-days 30 \
  --out-cert tls/mysql/client.crt \
  --out-key tls/mysql/client.key \
  --out-chain tls/mysql/client-ca.crt
```

`mysql-client` is a service principal — there is no `Operator` row
behind it. The leaf carries the `clientAuth` EKU; pymysql presents it
to mysqld during the handshake, and mysqld validates the chain
against the same CA the dashboard's browser cert chains to.

## 4. Bounce the database container

```bash
make db-down
make db-up
docker compose logs mysql | grep -i "ssl"
```

The compose bind mount drops `docker/mysql/conf.d/wg-manager-tls.cnf`
into `/etc/mysql/conf.d/`, which sets `require_secure_transport=ON`
and points mysqld at the certs you just minted. Log lines that
mention `SSL` or `TLS` are normal; what you do **not** want to see is
`Failed to set up SSL because of the following SSL library error`.

## 5. Wire the engine

Add to `.env`:

```ini
DATABASE_TLS_REQUIRED=true
DATABASE_TLS_CA_PEM=tls/mysql/client-ca.crt
DATABASE_TLS_CERT_PEM=tls/mysql/client.crt
DATABASE_TLS_KEY_PEM=tls/mysql/client.key
```

Then restart the API (`make run`) and any running worker
(`make worker`). The engine constructed by
`wg_manager.db._build_engine` now hands pymysql an
`ssl={ca, cert, key, check_hostname}` connect-args dict.

## 6. Smoke

From a TLS-aware mysql client:

```bash
mysql -h 127.0.0.1 -P 3307 -u wg --ssl-mode=REQUIRED \
      --ssl-ca=tls/mysql/client-ca.crt \
      --ssl-cert=tls/mysql/client.crt \
      --ssl-key=tls/mysql/client.key \
      -e "STATUS;"
```

Look for `SSL: Cipher in use is ...` in the output.

Connecting without `--ssl-mode=REQUIRED` (or with a stale CA) should
fail with `ERROR 9002 (HY000): The MySQL server is running with the
--require_secure_transport option`.

## 7. Cert renewal

Both `mysql` and `mysql-client` are 30-day leaves by default. Phase
2d CP4.3 ships `wg-manager certs renew` and a systemd-timer pattern
that walks the registry and re-issues anything inside the renewal
threshold; until that lands, the operator re-runs `make
mysql-tls-issue` + the `wg-manager certs issue --type mysql-client`
command above and bounces both processes.

## 8. Recovery — locked out of MySQL

If a cert expired and the API can no longer connect:

1. Set `DATABASE_TLS_REQUIRED=false` in `.env`.
2. Comment out the `./docker/mysql/conf.d:/etc/mysql/conf.d:ro` mount
   in `docker-compose.yml` (or edit
   `docker/mysql/conf.d/wg-manager-tls.cnf` to remove
   `require_secure_transport=ON`).
3. `make db-down && make db-up`.
4. Re-mint the certs as above.
5. Re-enable the flag + mount, bounce again.

The data volume (`wg_manager_mysql_data`) is untouched throughout —
this is a config-level recovery, not a data-level one.

## 9. Bootstrap on a TLS-enforced DB

What if the MySQL container is up with `require_secure_transport=ON`
but you've never minted certs into `tls/mysql/`? The §2 / §3 path
(`make mysql-tls-issue`, `wg-manager certs issue --type
mysql-client`) requires DB access to write the audit row — which the
TLS gate refuses without certs. Chicken-and-egg.

The script `scripts/bootstrap_mysql_tls_files.py` breaks the cycle by
going **straight to the PKI backend** to mint the four PEM files
without writing to the `certificate` table:

```bash
uv run python scripts/bootstrap_mysql_tls_files.py
```

It writes:

- `tls/mysql/server.crt` / `server.key` / `ca.crt` — mysqld material
- `tls/mysql/client.crt` / `client.key` / `client-ca.crt` —
  app/worker material

After the script finishes:

```bash
docker compose restart mysql

export DATABASE_TLS_REQUIRED=true
export DATABASE_TLS_CA_PEM=tls/mysql/client-ca.crt
export DATABASE_TLS_CERT_PEM=tls/mysql/client.crt
export DATABASE_TLS_KEY_PEM=tls/mysql/client.key

make migrate                          # now connects over TLS
uv run wg-manager operators list      # confirms the dance worked
```

Once the DB is reachable again, the operator may re-mint the same
identities through the normal `wg-manager certs issue --type mysql`
+ `--type mysql-client` paths to land audit rows for the certs that
are actually in production. The bootstrap script's job ends at
"DB reachable" — the canonical issuance path stays the CLI.
