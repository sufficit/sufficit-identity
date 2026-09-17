#!/usr/bin/env bash
# Runs the OpenID Foundation conformance suite against a disposable Sufficit
# Identity environment. See conformance/README.md.
#
# usage: conformance/run.sh [plan] [config-template]
#   plan defaults to the OpenID Connect Basic OP certification plan.
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

plan=${1:-"oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"}
template=${2:-config/oidcc-basic.template.json}
# Accepted results and protocol options are per plan; both are named after the
# template (config/<name>.template.json -> config/<name>.expected-*.json).
profile=$(basename "$template" .template.json)
export CONFORMANCE_EXPECTED_PREFIX=$profile
suite_tag=${CONFORMANCE_SUITE_TAG:-release-v5.2.4}
suite_dir=${CONFORMANCE_SUITE_DIR:-$here/.suite/$suite_tag}
results_dir=${CONFORMANCE_RESULTS_DIR:-$here/results}
project=${CONFORMANCE_PROJECT:-sufficit-identity-conformance}

# Throwaway credentials for a disposable environment; override in CI if wanted.
export CONFORMANCE_ALIAS=${CONFORMANCE_ALIAS:-sufficit-identity}
export CONFORMANCE_USER_NAME=${CONFORMANCE_USER_NAME:-conformance-user}
export CONFORMANCE_USER_PASSWORD=${CONFORMANCE_USER_PASSWORD:-Conformance-$(openssl rand -hex 12)-Aa1!}
export CONFORMANCE_CLIENT1_ID=${CONFORMANCE_CLIENT1_ID:-conformance-client-1}
export CONFORMANCE_CLIENT1_SECRET=${CONFORMANCE_CLIENT1_SECRET:-$(openssl rand -hex 24)}
export CONFORMANCE_CLIENT2_ID=${CONFORMANCE_CLIENT2_ID:-conformance-client-2}
export CONFORMANCE_CLIENT2_SECRET=${CONFORMANCE_CLIENT2_SECRET:-$(openssl rand -hex 24)}
# The suite publishes itself under this host name; the browser configuration
# has to anchor the callback match to it, because the authorization URL carries
# the same callback inside its redirect_uri parameter.
export CONFORMANCE_SUITE_BASE_URL=${CONFORMANCE_SUITE_BASE_URL:-https://localhost.emobix.co.uk:8443}
export CONFORMANCE_SUITE_TAG=$suite_tag
export CONFORMANCE_SUITE_DIR=$suite_dir

# FAPI 2.0 is opt-in in the product and stays off for the Basic profile run.
if [[ $profile == fapi2* ]]; then
    export CONFORMANCE_FAPI2=${CONFORMANCE_FAPI2:-true}
    export CONFORMANCE_DPOP=${CONFORMANCE_DPOP:-true}
    export CONFORMANCE_CLIENT_AUTHENTICATION=${CONFORMANCE_CLIENT_AUTHENTICATION:-private_key_jwt}
    export CONFORMANCE_PAR_LIFETIME=${CONFORMANCE_PAR_LIFETIME:-20}
else
    export CONFORMANCE_FAPI2=${CONFORMANCE_FAPI2:-false}
    export CONFORMANCE_DPOP=${CONFORMANCE_DPOP:-false}
    export CONFORMANCE_CLIENT_AUTHENTICATION=${CONFORMANCE_CLIENT_AUTHENTICATION:-client_secret_basic}
fi

if [[ ! -f "$suite_dir/scripts/run-test-plan.py" ]]; then
    mkdir -p "$(dirname "$suite_dir")"
    git clone --quiet --depth 1 --branch "$suite_tag" \
        https://gitlab.com/openid/conformance-suite.git "$suite_dir"
fi

# Base images are pulled up front with retries: this environment intermittently
# fails IPv6 registry connections, which would otherwise abort a build midway.
pull_with_retry() {
    local image=$1 attempt
    for attempt in 1 2 3; do
        if docker image inspect "$image" > /dev/null 2>&1; then
            return 0
        fi
        if docker pull --quiet "$image" > /dev/null 2>&1; then
            return 0
        fi
        echo "[conformance] pull of $image failed (attempt $attempt)" >&2
        sleep 5
    done
    echo "[conformance] giving up on $image" >&2
    return 1
}
for image in \
    mcr.microsoft.com/dotnet/sdk:10.0.302 \
    mcr.microsoft.com/dotnet/aspnet:10.0.10 \
    mariadb:10.4.34 \
    nginx:1.27-alpine \
    mongo:6.0.13 \
    python:3.12-slim \
    "registry.gitlab.com/openid/conformance-suite:$suite_tag" \
    "registry.gitlab.com/openid/conformance-suite/nginx:$suite_tag"
do
    pull_with_retry "$image"
done

mkdir -p "$results_dir"
rendered="$results_dir/plan-config.json"
render_plan_config() {
    local client1_jwk=null client2_jwk=null
    if [[ -f "$results_dir/client-keys.json" ]]; then
        client1_jwk=$(python3 -c 'import json,sys;print(json.dumps(json.load(open(sys.argv[1]))[sys.argv[2]]))' \
            "$results_dir/client-keys.json" "$CONFORMANCE_CLIENT1_ID")
        client2_jwk=$(python3 -c 'import json,sys;print(json.dumps(json.load(open(sys.argv[1]))[sys.argv[2]]))' \
            "$results_dir/client-keys.json" "$CONFORMANCE_CLIENT2_ID")
    fi
    sed -e "s|{ALIAS}|$CONFORMANCE_ALIAS|g" \
    -e "s|{SUITE_BASE_URL}|$CONFORMANCE_SUITE_BASE_URL|g" \
    -e "s|{USER_NAME}|$CONFORMANCE_USER_NAME|g" \
    -e "s|{USER_PASSWORD}|$CONFORMANCE_USER_PASSWORD|g" \
    -e "s|{CLIENT1_ID}|$CONFORMANCE_CLIENT1_ID|g" \
    -e "s|{CLIENT1_SECRET}|$CONFORMANCE_CLIENT1_SECRET|g" \
    -e "s|{CLIENT2_ID}|$CONFORMANCE_CLIENT2_ID|g" \
    -e "s|{CLIENT2_SECRET}|$CONFORMANCE_CLIENT2_SECRET|g" \
    -e "s|\"{CLIENT1_JWK}\"|$client1_jwk|g" \
    -e "s|\"{CLIENT2_JWK}\"|$client2_jwk|g" \
        "$template" > "$rendered"
    chmod 600 "$rendered"
}

compose=(docker compose --project-name "$project" --file "$here/docker-compose.yml")
cleanup() {
    if [[ -z ${CONFORMANCE_KEEP:-} ]]; then
        "${compose[@]}" logs --no-color identity > "$results_dir/identity.log" 2>&1 || true
        "${compose[@]}" logs --no-color > "$results_dir/environment.log" 2>&1 || true
        "${compose[@]}" down --volumes --remove-orphans > /dev/null 2>&1 || true
        rm -f "$results_dir/client-keys.json"
    fi
}
trap cleanup EXIT

rm -f "$results_dir/client-keys.json"
"${compose[@]}" up --detach --build --wait db identity identity-op mongodb suite-server suite-nginx
# --build: the seeder is not part of the "up" list, so compose would happily
# reuse an image built from an older working tree.
"${compose[@]}" run --rm --build seeder

# Rendered after seeding: with private_key_jwt the plan configuration carries
# the private keys whose public halves were just registered on the clients.
render_plan_config

set +e
"${compose[@]}" run --rm \
    -e CONFORMANCE_PLAN="$plan" \
    runner
status=$?
set -e

echo "[conformance] plan finished with exit code $status; results in $results_dir"
exit $status
