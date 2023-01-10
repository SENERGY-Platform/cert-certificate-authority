<a href="https://github.com/SENERGY-Platform/cert-certificate-authority/actions/workflows/test.yml" rel="nofollow">
        <img src="https://github.com/SENERGY-Platform/cert-certificate-authority/actions/workflows/test.yml/badge.svg" alt="Tests" />
</a>

<a href="https://github.com/SENERGY-Platform/cert-certificate-authority/actions/workflows/dev.yml" rel="nofollow">
    <img src="https://github.com/SENERGY-Platform/cert-certificate-authority/actions/workflows/dev.yml/badge.svg" alt="Deployment Dev" />
</a>

<a href="https://github.com/SENERGY-Platform/cert-certificate-authority/actions/workflows/prod.yml" rel="nofollow">
    <img src="https://github.com/SENERGY-Platform/cert-certificate-authority/actions/workflows/prod.yml/badge.svg" alt="Deployment Prod" />
</a>

# Configuration 
| Environment Variable | DEFAULT | Function |
| -------------------- | ------- | -------- |
| DB_DRIVER            | postgres | Database driver |
| DB_USERNAME | user | Database user |
| DB_PASSWORD | password | Database password |
| DB_ADDR | db | Host of the database |
| DB_DATABASE | db | Database name |
| DEBUG | 0 | Enable debugging mode |
| SERVER_PORT | 8080 | Server Port |
| CA_CERT_PATH | /etc/certs/ca.crt | Path to the CA certificate |
| PRIVATE_KEY_PATH | /etc/certs/key.key | Path to the CA private key |


# Start
To start this service and a database, run `docker compose up -f deployments/docker-compose.yml`

# Sign
Use `/sign` to sign a certificate signing request (CSR) and provide the expected expiration time of the certificate and hostnames that shall be used in the subject alternative names fields.

```json
{
  "crt": "-----BEGIN CERTIFICATE REQUEST-----\n\nMIIEhTCCAm0CAQAwQDELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx\n\nDDAKBgNVBAoMA29yZzEOMAwGA1UEAwwFYWRtaW4wggIiMA0GCSqGSIb3DQEBAQUA\n\nA4ICDwAwggIKAoICAQDFFWFSwXq5D5f12/Mw18rFuFq+21nNm//fv4SXayec9wa/\n\nlA/Gc/oYSbL0xMCrGWc4/99hogSp4XeIytJHUl44pFTcHdexn6908Vb6GxN7Kswm\n\nuAFmmaOu1LYruEZAhZjAZUn9VyQTACkUqHUHEI3p+jzl7QL0wO1MgPgi9Egy6bIR\n\nvrPQA/ea6Dv4KF/XfPDXoOCkivGbTpu05mdzW7Ap+jtwD+52HG3okwJB/eJWyX4F\n\nsPvjrE+eOy6vNVxRwauw1omrW6IGPqGwNd+g7R2PQj6tyaOFQ1qs9powrjb17abo\n\nv5wOwhVKjkfQOhunO+GQ8puLROHdyrz2Hudebjj4ToVNBR1pbjLJQmhh9YqEOxod\n\nofD4FMzGbKwa8LGCRSMriaCfA1DL2ATY8I48PsdM0UykfkOro1F/LpzumrkUek6t\n\nO0CKrOa1IrFlOsPBw5xkbTKabbVvPuzfaY28TVZUJEcv16m/V4p2l33pg2p0xpvg\n\nqt6l4/cwwunDtKWweP0ONcM6pSg97V2MhJUwAC+eUgTOxc63yqFeK8dEgGP8GR87\n\nQfr2mRW/zrY1hgnLL78/LK5HNj8SkzQEZAVJ6hGrc1XilSfHy9z3PluU2P9bUjuM\n\nbz86DID/QppNTr5t7Q+gQ8Ho+GtbUrtkuPaE8W9I6eLqE5VbCKOkAC4JFglEBQID\n\nAQABoAAwDQYJKoZIhvcNAQELBQADggIBAC6pxAIHNFGe5qT4WvqzaY9bhkO27qWL\n\neOeYammnM63RjGpSAzPyreqaAq4zf0bdnfJ0WrGd+MV75oyVsTAxqaVMrWHy5c13\n\nQcIwccvqp/7Pzo//UVKVtxajU3xDDdjaB+Ng8TxAjSDS3hmwUlcQkVuNPbTatG9t\n\nKZQYX0g7Wm2im1l6NwJG9EczjT11VJkLqhbsHx22m20C1O3X2JZy9xxx+Gsi9b2f\n\n7GQAQ/m7313w/AuN/AMkrnO19iPCD9zcDlsvjDm6m72gADVht+XPkvZ9+T3GmdZv\n\nbyD/ZpgnuEMhccz5+6Uri3LcBwGou7r0R+hDLAI29YZm/zY7uNDP8twnbKsrJkp7\n\niHZvMyTVL++tpAGv2Ztpw6QO48gsJhRitD88atvMn7PzGvpnMZ4K3h1JioUyvF6V\n\nBvdlDDt00XA71dUa2S8Wwi9AbBH0nJ5q8f5r1w9leeT4bMPCnSPAbKs+VF5dCInk\n\nP32dgc0C0hzWvrod4fzgcGU/JE5uCGTEktf+AGh4EPUhwKGRNh78Qts85nVVAPLy\n\n9YJIIOdTcktye1j2glr7wc6f3grTgB0JwKQzRHDDHDIkC1pexawUcDTo8+RP5F5T\n\nDEwdgmXavwJXFPSE1dZbBowX4QKXfDGvDckZg2336SUoTS1KzZNS8o2nL0pYNVKo\n\nfjgZ6fnblEXr\n\n-----END CERTIFICATE REQUEST-----",
   "expiration": 24,
    "hostnames": ["localhost"]
}
```

# Revokation
Use `/revoke` to revoke a certificate. The payload should contain the `serial` id in decimal format, the `authority_key_id` from the certificate and the revocation reason.

```json
{
    "serial": "600456405011773660801227315629767572664543642005",
    "authority_key_id": "e7f9c3000ef018f0c02b5cd6d21891db9bb84588",
    "reason": "superseded"
}
```

# Validation
Use `/ocsp` to check the revocation status of the certificate.
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\nMIICpjCCAk2gAwIBAgIUJ8XFaEt2OZc3nWlZwENFg+Xzb9cwCgYIKoZIzj0EAwIw\ngYoxCzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdFbmdsYW5kMQ8wDQYDVQQHEwZMb25k\nb24xFzAVBgNVBAoTDkN1c3RvbSBXaWRnZXRzMR0wGwYDVQQLExRDdXN0b20gV2lk\nZ2V0cyBIb3N0czEgMB4GA1UEAxMXaG9zdC5jdXN0b20td2lkZ2V0cy5jb20wHhcN\nMjIxMTA0MTM0NTAwWhcNMjMxMTA0MTM0NTAwWjBUMQswCQYDVQQGEwJBVTETMBEG\nA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkg\nTHRkMQ0wCwYDVQQDEwRzZXBsMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDG\nIQiecfFLdH60NdEVpotX3vX59ui7WlGtUqUprkYCz2Z0sbCue8+OLTEyuCcYlqTa\nuXbA7ofkvEBGyrOiqy00Hutskh/Cf1gDYVonaePiMrFOp4H4C8Ki4BlzkkX3+UIf\nJQvTWjup1pXLd/23aQYjJpE6xKIBMMPyNg1FJzFH9QIDAQABo38wfTAOBgNVHQ8B\nAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB\n/wQCMAAwHQYDVR0OBBYEFNaLUFrjU9f0TO+lIRcVdeilvgWeMB8GA1UdIwQYMBaA\nFOf5wwAO8BjwwCtc1tIYkdubuEWIMAoGCCqGSM49BAMCA0cAMEQCIH5VHO0xJQcH\nnR6ufFAfiIpNbmHor1TQF/5BR/XotB2eAiAPsAmRG5VOQMGR0di6fijCsSqsq3hL\nX+k3jdvy+wfhgA==\n-----END CERTIFICATE-----\n",
  "status": "good"
}

## OpenAPI generation
`swag init -g cmd/main.go -o api`
