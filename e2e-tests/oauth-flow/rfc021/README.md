This test can be executed against multiple SQL databases.
It's executed (by running `./run-test.sh`) on all supported databases (postgres, sqlite, mysql, sqlserver) by default.
To perform the test on a specific database, run `./do-test.sh <database>` where `<database>` is one of the supported databases (postgres, sqlite, mysql, sqlserver).

### sqlserver
By default, the container generates a new certificate at startup. 
Currently, this generated certificate may contain a negative serial number which is against the RFC.
Since GO 1.23, the negative serials numbers no longer pass validation. This can be disabled using `GODEBUG=x509negativeserial=1`. (In go 1.23 the default flag changed from 1 to 0.)
As a workaround we mount our own certificate. https://github.com/microsoft/mssql-docker/issues/895

Add the following config to the `sqlserver.yml`
```yaml
services:  
  db:
    volumes:
      - "./sqlserver.conf:/var/opt/mssql/mssql.conf"
      - "./sqlserver.key:/etc/ssl/mssql.key:ro" # technically this should be mounted under /etc/ssl/private, but that results in permission issues
      - "./sqlserver.pem:/etc/ssl/certs/mssql.pem:ro"
```

### certificate renewal
First check the latest version if this (and other issues) have been fixed
If not, regen certificates using
```bash
openssl req -x509 -nodes -newkey rsa:2048 -subj '/CN=mssql' -addext "subjectAltName = DNS:mssql" -keyout sqlserver.key -out sqlserver.pem -days 365
```