# WebAuthn Level 2 / FIDO2 — passkeys

| | |
|---|---|
| Role | Relying Party |
| Coverage | **B — Substantial** |
| Origin | ASP.NET Core Identity 10 (native), with in-house service and UI |
| Spec | https://www.w3.org/TR/webauthn-2/ |

## Base

There is no third-party FIDO2 library. Support is **native to .NET 10**: the
`AppDbContext` declares the ninth generic argument `IdentityUserPasskey<string>`,
which makes `AddEntityFrameworkStores` register `IUserPasskeyStore` and enables
the `AddOrUpdatePasskeyAsync`, `GetPasskeysAsync`, `RemovePasskeyAsync` and
`FindByPasskeyIdAsync` methods on `UserManager`, and `CheckPasskeySignIn` on
`SignInManager` (`src/sts/ServiceCollectionExtensions.cs:488-496`).

The table is `userpasskeys` (`src/core/Data/Mapping/PasskeyMapping.cs`).

## Configuration

| Key | Effect |
|---|---|
| `Passkeys:RelyingPartyId` | Becomes `IdentityPasskeyOptions.ServerDomain` (`:445-451`) |
| `Passkeys:MaximumCredentialsPerAccount` | Default 10 |
| `Passkeys:MaximumNameLength` | Default 100 |
| `Passkeys:MaximumCredentialPayloadBytes` | Default 131,072 |

The limits are checked before attestation
(`src/sts/AspNetCoreIdentityPasskeyService.cs:70`, `:119`), which prevents an
authenticated user from inflating the table.

## Ceremony

| Step | Endpoint |
|---|---|
| Creation options | `POST /connect/…/creation-options` — requires authentication |
| Registration | `POST …/register` — requires authentication |
| Request options | `POST …/request-options` — anonymous |
| Authentication | `POST …/authenticate` — anonymous |

`src/sts/Controllers/AccountPasskeysController.cs:23-97`. Origin, `RP ID` and
challenge validation are handled by the framework.

## Ceremony state outside the cookie

ASP.NET Identity stores the WebAuthn challenge in the temporary
`TwoFactorUserId` scheme. Keeping it in the cookie produces a response header
larger than the default buffer of several reverse proxies. That's why the
protected ticket is stored server-side and the browser only receives a random
lookup key (`PasskeyAuthenticationTicketStore`, registered in
`src/sts/ServiceCollectionExtensions.cs:452-464`).

## Integration with the rest of the system

- A verified passkey counts as MFA in step-up policies.
- Registration and removal emit CAEP `device-change` and `credential-change`
  (`AspNetCoreIdentityPasskeyService.cs:202`).
- Passkey mutation goes through `CredentialMutationSecurityCoordinator`, which
  rotates the security stamp and revokes sessions.

## Gaps

- No attestation verification against FIDO MDS metadata: the attestation is
  accepted without checking the authenticator model against a list.
- No policy to require authenticators with mandatory user verification.
- No *conditional UI* / autofill documented as a contract.

## Tests

`AccountPasskeyServiceTests`, `AccountPasskeysControllerTests`,
`CredentialMutationSecurityTests`.
