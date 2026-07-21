# syntax=docker/dockerfile:1
#
# =============================================================================
# Sufficit Identity STS — multi-stage container build.
#
# WHAT THIS BUILDS: publishes src/sts (Sufficit.Identity.STS, the headless
# OAuth/OIDC host) together with the sibling Blazor Server UI it hosts
# in-process (login/consent/logout/manage pages).
#
# -----------------------------------------------------------------------------
# BUILD CONTEXT REQUIREMENT — READ BEFORE BUILDING
# -----------------------------------------------------------------------------
# src/sts/Sufficit.Identity.STS.csproj references the sibling
# sufficit-identity-ui repo via an UNCONDITIONAL <ProjectReference
# Include="..\..\..\sufficit-identity-ui\src\Sufficit.Identity.UI\..."/>.
# Unlike Sufficit.Communication (referenced from src/server, which already
# carries a Condition="Exists(...)"/NuGet Version="1.*" fallback pair), there
# is currently NO published `Sufficit.Identity.UI` NuGet package to fall back
# to (checked nuget.org: no such package exists as of 2026-07-20) — so this
# image genuinely CANNOT be built from this repo alone today. The sibling
# UI source must be supplied as a second Docker build context.
#
# The OTHER sibling ProjectReferences this solution transitively pulls in
# (Sufficit.Communication, and via IT, Sufficit.Base/Utils/EFData/Json) DO
# already carry that Condition="Exists(...)" + NuGet-fallback pair in their
# own .csproj files — so as long as those sibling repo folders are simply
# absent from both contexts below, MSBuild resolves them from NuGet
# automatically. Only sufficit-identity (this repo) and sufficit-identity-ui
# need to be supplied.
#
# BUILD (Docker Buildx / BuildKit — additional named build context):
#
#   cd sufficit-identity      # this repo; context = "." (repo root)
#   docker build \
#     --build-context ui=../sufficit-identity-ui \
#     -t sufficit-identity-sts:latest \
#     .
#
# This keeps the DEFAULT build context this repo alone, so .dockerignore at
# this repo's root (excluding appsettings*.json — see SECRETS below) applies
# normally; the sibling UI repo is supplied as the separately-named "ui"
# context, referenced below via `COPY --from=ui`.
#
# (Fallback for Docker builds without --build-context support: copy/checkout
# sufficit-identity-ui next to this repo, point the build context at their
# common parent directory, and adjust the two COPY lines below to
# `COPY sufficit-identity/ ...` / `COPY sufficit-identity-ui/ ...` — mirrors
# .github/workflows/ci.yml's checkout layout. In that mode, remember
# .dockerignore only auto-applies to the context ROOT, so exclude
# appsettings*.json there some other way, e.g. -f pointing at a copy of this
# Dockerfile plus a `<dockerfile>.dockerignore` at the parent context root.)
#
# SECRETS: appsettings.json / appsettings.Development.json are real,
# untracked, developer-local files (see .gitignore) that may contain live
# credentials (DB, RabbitMQ, OAuth secrets — see docs/EVALUATION-2026-07-20.md
# §2 C4). .dockerignore at this repo's root excludes both so a `docker build`
# run from a developer's working tree never bakes them into an image layer;
# the RUN step below also deletes them defensively in case some other build
# invocation bypassed .dockerignore. Configure the running container via
# environment variables / mounted volumes / secrets instead
# (appsettings.json.template documents every key).
# =============================================================================

# Base images pinned to the exact .NET 9 patch version that matches the
# package graph in Directory.Packages.props (Microsoft.EntityFrameworkCore
# 9.0.18, Identity.EntityFrameworkCore 9.0.18, DataProtection.EntityFrameworkCore
# 9.0.18, Mvc.Testing 9.0.18, Sqlite 9.0.18 — all on the same patch). The
# 9.0 floating tag was previously used; pinning the patch version makes builds
# reproducible and prevents silent rollforward when Microsoft ships a new patch.
#
# TODO(supply-chain): additionally pin by SHA digest for cryptographic
# immutability, once a digest-fetching tool (crane / skopeo / docker manifest
# inspect) is available in the build environment:
#   crane digest mcr.microsoft.com/dotnet/sdk:9.0.18
#   crane digest mcr.microsoft.com/dotnet/aspnet:9.0.18
# then append `@sha256:<digest>` to each ARG default. The patch tag alone is
# immutable-in-practice (Microsoft does not move 9.0.18 once shipped) but is
# not a cryptographic guarantee the way a digest is.
ARG DOTNET_SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:9.0.18
ARG DOTNET_RUNTIME_IMAGE=mcr.microsoft.com/dotnet/aspnet:9.0.18

# -----------------------------------------------------------------------------
# Stage 1: restore + publish
# -----------------------------------------------------------------------------
FROM ${DOTNET_SDK_IMAGE} AS build
WORKDIR /src

# Both repos, laid out as siblings under /src so the existing relative
# ProjectReference paths (../../../sufficit-identity-ui/... and, from the UI
# project, ../../../sufficit-identity/...) resolve unmodified. Each repo
# carries its own Directory.Build.props/Directory.Packages.props at its own
# root, discovered by MSBuild walking up from each .csproj.
COPY . /src/sufficit-identity/
COPY --from=ui . /src/sufficit-identity-ui/

# Defense in depth on top of .dockerignore — see the SECRETS note above.
RUN rm -f /src/sufficit-identity/src/sts/appsettings.json \
          /src/sufficit-identity/src/sts/appsettings.Development.json

RUN dotnet restore /src/sufficit-identity/src/sts/Sufficit.Identity.STS.csproj

RUN dotnet publish /src/sufficit-identity/src/sts/Sufficit.Identity.STS.csproj \
      --configuration Release \
      --no-restore \
      --output /app/publish

# -----------------------------------------------------------------------------
# Stage 2: runtime
# -----------------------------------------------------------------------------
FROM ${DOTNET_RUNTIME_IMAGE} AS final
WORKDIR /app

# Non-root (defense in depth — nothing this process does needs root inside
# the container).
RUN groupadd --gid 1654 sufficit \
    && useradd --uid 1654 --gid sufficit --create-home --shell /usr/sbin/nologin sufficit

# Install curl as root (BEFORE the USER directive — apt-get needs root) so
# the HEALTHCHECK below can probe the liveness endpoint. The aspnet:9.0
# Debian Slim base does NOT ship curl or wget by default. --no-install-
# recommends + apt list cleanup keep the layer small (~5 MB).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

USER sufficit

COPY --from=build /app/publish .

# Configuration is supplied at deploy time (env vars / mounted secrets /
# orchestrator config) — see appsettings.json.template in this repo for every
# key, and docs/EVALUATION-2026-07-20.md §10 (P0 #9) for the production
# checklist (Certificates, TrustedProxies, cookie SecurePolicy, real
# RabbitMQ, etc.). Nothing environment-specific is baked into this image.
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

# Container-level liveness probe (H4). /health is liveness-only in Program.cs
# (HealthCheckOptions.Predicate=_=>false skips all dependency checks → 200
# once Kestrel is bound). Deliberately NOT /health/ready (which runs the DB
# check) — orchestrators should use readiness as a SEPARATE probe concept
# (e.g. Kubernetes readinessProbe) so a DB blip doesn't cause a thundering-
# herd container restart. start-period gives the .NET process room to boot
# before Docker starts counting failures.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8080/health || exit 1

ENTRYPOINT ["dotnet", "Sufficit.Identity.STS.dll"]
