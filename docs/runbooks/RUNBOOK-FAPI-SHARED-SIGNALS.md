# FAPI 2.0, JARM and Shared Signals rollout

These capabilities ship disabled. Enabling them is a client/integration
rollout, not a declaration of OpenID Foundation certification.

## FAPI 2.0

1. Provision a confidential client with `private_key_jwt` or validated mTLS.
2. Grant the pushed-authorization endpoint permission and require PAR.
3. Confirm the client sends `response_type=code`, `redirect_uri`, PKCE S256 and,
   for DPoP, `dpop_jkt` inside the authenticated PAR request.
4. Enable DPoP (including shared replay/nonce state before multiple replicas)
   or configure certificate validation at the mTLS terminator.
5. Add only the rehearsed client id under `Fapi2:ClientIds`, enable the profile,
   and run the official FAPI conformance suite against the public TLS endpoint.

The profile globally tightens authorization-code lifetime to at most 60 seconds
and PAR `request_uri` lifetime to less than 600 seconds. The current refresh
token behavior must also be assessed against the selected FAPI ecosystem
profile before claiming conformance.

## JARM

Set `Jarm:Enabled=true` only for clients that validate the STS signing key from
JWKS and understand one of `query.jwt`, `fragment.jwt`, `form_post.jwt` or
`jwt`. JARM is independent of FAPI 2.0. Test success and error responses,
signature rotation and clock skew before production use.

On an installed host, enable or roll back the capability explicitly:

```bash
/opt/sufficit-identity/helpers/security-rollout.sh enable-jarm
systemctl restart sufficit-identity

# rollback
/opt/sufficit-identity/helpers/security-rollout.sh disable-jarm
systemctl restart sufficit-identity
```

## SSF/CAEP

Configure receivers through secret-backed environment variables:

```text
Sufficit__Identity__SharedSignals__Enabled=true
Sufficit__Identity__SharedSignals__Receivers__0__Id=receiver-a
Sufficit__Identity__SharedSignals__Receivers__0__Audience=https://receiver.example/events
Sufficit__Identity__SharedSignals__Receivers__0__Endpoint=https://receiver.example/push
Sufficit__Identity__SharedSignals__Receivers__0__Authorization=Bearer <secret>
```

Verify `/.well-known/ssf-configuration`, validate a signed
`session-revoked` SET against the advertised JWKS, and observe a real logout at
the receiver. Direct delivery has bounded retries but no durable outbox; add a
queue/outbox before the integration requires delivery across process restarts.
The optional SSF stream-management API is intentionally absent from discovery.
