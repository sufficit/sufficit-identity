# Deployment configuration

## castrum-apps test environment

The versioned source of truth for the Sufficit Identity nginx virtual host in
the test environment is
[`helpers/nginx-identity.conf`](../helpers/nginx-identity.conf). The installed
copy is `/etc/nginx/sites-available/sufficit-identity-test`, enabled through
the corresponding symlink under `/etc/nginx/sites-enabled`.

Operational changes must be made in the repository first, validated with
`nginx -t`, deployed to the installed path and committed. This keeps the
server from becoming an untracked second source of truth.

The application owns authentication state. In particular, passkey
authentication tickets are protected and stored server-side by
`PasskeyAuthenticationTicketStore`; nginx must not be made responsible for
accommodating oversized passkey response cookies. The
`large_client_header_buffers` directive in the virtual host only covers large
request headers received from clients.

After deployment, compare the effective virtual host with the versioned file
and run:

```bash
nginx -t
```

Only reload nginx after the syntax check succeeds.
