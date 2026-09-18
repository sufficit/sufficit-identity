# Host profiles: one binary, two planes

`Sufficit:Identity:HostProfile` says which plane a process serves. The binary,
the database and the settings file stay the same; the profile decides which
modules the host composes.

| Profile | Composes | Leaves out |
|---|---|---|
| `All` (default) | Everything the configuration enables | — |
| `Sts` | The public sign-in UI, and the token endpoints the STS always registers | Management API, management console, Vault console, SCIM |
| `Admin` | Management API, management console, Vault console, SCIM | Public sign-in UI |

## Why it narrows and never widens

A profile can only remove what the configuration already enabled. That is what
lets the three production nodes keep sharing one settings file while running
different processes: the systemd unit picks the profile, the settings say what
exists at all. Turning a module on is still a configuration decision, in one
place.

What a profile leaves out is logged once at startup:

```
Identity host profile Sts; modules=public-ui; excludedByProfile=management,management-ui,scim
```

A missing endpoint should be explained by that line, not by a 404.

## What it buys

The process that mints tokens stops carrying the management API, the consoles
and SCIM: less code reachable from the network on the host that holds the
signing keys, and the administration plane can be scaled or restarted without
touching sign-in.

## What it does not do yet

The STS itself is still composed in both profiles, because the administration
plane validates the tokens it receives. An `Admin` host therefore still has the
OpenIddict validation stack — what it no longer has is every administrative
surface on the same process as sign-in, which was the point of A7 in the
evaluation.

Splitting issuance from validation inside the STS is the next step if the
separation ever needs to go further.

## Running it

```ini
# /etc/systemd/system/sufficit-identity.service.d/profile.conf
[Service]
Environment=Sufficit__Identity__HostProfile=Sts
```

Covered by `IdentityHostProfileTests`.
