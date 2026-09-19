#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: package-release.sh [output-directory]

Publishes the current clean Git revision and creates a configuration-free
release archive. Production appsettings and certificates are deliberately not
packaged; prepare-cluster-release.sh inherits them from each active node.
EOF
}

if [[ $# -gt 1 ]]; then
    usage
    exit 2
fi

script_directory=$(cd -- "$(dirname -- "$0")" && pwd)
repository=$(cd -- "${script_directory}/.." && pwd)
output_root=${1:-${repository}/_publish/releases}

if [[ -n $(git -C "${repository}" status --porcelain --untracked-files=normal) ]]; then
    echo "[package] Refusing to package a dirty worktree." >&2
    exit 1
fi

revision=$(git -C "${repository}" rev-parse HEAD)
short_revision=$(git -C "${repository}" rev-parse --short=7 HEAD)
release_name=${IDENTITY_RELEASE_NAME:-$(date -u +%Y%m%dT%H%M%SZ)-${short_revision}}
if [[ -z ${release_name} || ${release_name} == */* || ${release_name} == .* || \
    ${release_name} == *[!A-Za-z0-9._-]* ]]; then
    echo "[package] Release name must be a non-empty safe identifier." >&2
    exit 2
fi

mkdir -p -- "${output_root}"
output_root=$(cd -- "${output_root}" && pwd)
archive="${output_root}/${release_name}.tar.gz"
if [[ -e ${archive} ]]; then
    echo "[package] Archive already exists: ${archive}" >&2
    exit 1
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/sufficit-identity-package.XXXXXX")
release_directory="${temporary_directory}/release"
cleanup() {
    rm -rf -- "${temporary_directory}"
}
trap cleanup EXIT INT TERM
mkdir -p -- "${release_directory}"

dotnet publish \
    "${repository}/src/server/Sufficit.Identity.Server.csproj" \
    -c Release --no-restore -o "${release_directory}" >&2
cp -a -- "${repository}/helpers" "${release_directory}/helpers"
printf '%s\n' "${revision}" > "${release_directory}/REVISION"

for required in \
    Sufficit.Identity.Server.dll \
    Sufficit.Identity.Server.staticwebassets.endpoints.json \
    helpers/activate-cluster-release.sh \
    helpers/activate-release.sh \
    helpers/bootstrap-release.sh \
    helpers/package-release.sh \
    helpers/prepare-cluster-release.sh \
    helpers/preserve-release-configuration.sh \
    helpers/prestart.sh \
    REVISION
do
    if [[ ! -s ${release_directory}/${required} ]]; then
        echo "[package] Required release file is missing: ${required}" >&2
        exit 1
    fi
done

if [[ ! -d ${release_directory}/wwwroot/_content/Sufficit.Blazor.UI ]]; then
    echo "[package] Shared Sufficit.Blazor.UI assets are missing." >&2
    exit 1
fi

if find "${release_directory}" -maxdepth 1 -type f \
    \( -name 'appsettings*.json' -o -name 'certificate*.pfx' \) \
    -print -quit | grep -q .
then
    echo "[package] Refusing to package runtime configuration or certificates." >&2
    exit 1
fi

# The runtime preflight refuses any group- or other-writable release path, and
# tar extracted as root keeps the archived modes. A workstation umask of 0002
# would otherwise produce a release that only fails once the service restarts.
chmod -R go-w -- "${release_directory}"

# The opposite failure is quieter. The static-web-asset compression step writes
# some .br files through a temporary file created 0600, whatever the umask, and
# the service does not run as the user that extracts the release. Those files
# answer 500, the browser falls back to nothing, and a component that imports
# its own module takes the whole circuit down — the sign-in page's language
# selector did, in production, on 2026-09-19. The archive holds no secrets (the
# check above refuses them), so everything in it is meant to be readable.
chmod -R a+rX -- "${release_directory}"
unreadable=$(find "${release_directory}" ! -perm -o=r -print -quit)
if [[ -n ${unreadable} ]]; then
    echo "[package] Release file is not readable by the service: ${unreadable#"${release_directory}/"}" >&2
    exit 1
fi

tar -C "${release_directory}" -czf "${archive}" .
chmod 0644 "${archive}"
archive_sha256=$(sha256sum "${archive}" | awk '{print $1}')

printf 'RELEASE_NAME=%s\nREVISION=%s\nARCHIVE=%s\nARCHIVE_SHA256=%s\n' \
    "${release_name}" "${revision}" "${archive}" "${archive_sha256}"
