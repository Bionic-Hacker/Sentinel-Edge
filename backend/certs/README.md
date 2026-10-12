# Certificate authorities the API trusts beyond the system store

`rds-global-bundle.pem` holds Amazon RDS's certificate authorities. In AWS the API connects to
PostgreSQL with `sslmode=verify-full`: it checks that the server's certificate chains to one of
these CAs **and** names the host it dialled (T-DB-04). The images carry it at
`/srv/certs/rds-global-bundle.pem`:

- the API image, from this folder;
- the dbadmin image (`db/Dockerfile`), passed in as the `certs` build context.

Refresh it with `make rds-ca`, review the diff (it only ever adds or retires CAs), and commit.
The bundle is public; it is committed so every image build is reproducible and reviewable.
Locally the file is not used (the local database is reached over a private Docker network).
