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
OCSP can be used to check the revocation status of the certificate.
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\nMIICpjCCAk2gAwIBAgIUJ8XFaEt2OZc3nWlZwENFg+Xzb9cwCgYIKoZIzj0EAwIw\ngYoxCzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdFbmdsYW5kMQ8wDQYDVQQHEwZMb25k\nb24xFzAVBgNVBAoTDkN1c3RvbSBXaWRnZXRzMR0wGwYDVQQLExRDdXN0b20gV2lk\nZ2V0cyBIb3N0czEgMB4GA1UEAxMXaG9zdC5jdXN0b20td2lkZ2V0cy5jb20wHhcN\nMjIxMTA0MTM0NTAwWhcNMjMxMTA0MTM0NTAwWjBUMQswCQYDVQQGEwJBVTETMBEG\nA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkg\nTHRkMQ0wCwYDVQQDEwRzZXBsMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDG\nIQiecfFLdH60NdEVpotX3vX59ui7WlGtUqUprkYCz2Z0sbCue8+OLTEyuCcYlqTa\nuXbA7ofkvEBGyrOiqy00Hutskh/Cf1gDYVonaePiMrFOp4H4C8Ki4BlzkkX3+UIf\nJQvTWjup1pXLd/23aQYjJpE6xKIBMMPyNg1FJzFH9QIDAQABo38wfTAOBgNVHQ8B\nAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB\n/wQCMAAwHQYDVR0OBBYEFNaLUFrjU9f0TO+lIRcVdeilvgWeMB8GA1UdIwQYMBaA\nFOf5wwAO8BjwwCtc1tIYkdubuEWIMAoGCCqGSM49BAMCA0cAMEQCIH5VHO0xJQcH\nnR6ufFAfiIpNbmHor1TQF/5BR/XotB2eAiAPsAmRG5VOQMGR0di6fijCsSqsq3hL\nX+k3jdvy+wfhgA==\n-----END CERTIFICATE-----\n",
  "status": "good"
}
```