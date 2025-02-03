#!/bin/bash
#
# Copyright 2018 The Outline Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Script to install the Outline Server docker container, a watchtower docker container
# (to automatically update the server), and to create a new Outline user.

# You may set the following environment variables, overriding their defaults:
# SB_IMAGE: The Outline Server Docker image to install, e.g. quay.io/outline/shadowbox:nightly
# CONTAINER_NAME: Docker instance name for shadowbox (default shadowbox).
#     For multiple instances also change SHADOWBOX_DIR to an other location
#     e.g. CONTAINER_NAME=shadowbox-inst1 SHADOWBOX_DIR=/opt/outline/inst1
# SHADOWBOX_DIR: Directory for persistent Outline Server state.
# ACCESS_CONFIG: The location of the access config text file.
# SB_DEFAULT_SERVER_NAME: Default name for this server, e.g. "Outline server New York".
#     This name will be used for the server until the admins updates the name
#     via the REST API.
# SENTRY_LOG_FILE: File for writing logs which may be reported to Sentry, in case
#     of an install error. No PII should be written to this file. Intended to be set
#     only by do_install_server.sh.
# WATCHTOWER_REFRESH_SECONDS: refresh interval in seconds to check for updates,
#     defaults to 3600.
#
# Deprecated:
# SB_PUBLIC_IP: Use the --hostname flag instead
# SB_API_PORT: Use the --api-port flag instead

# Requires curl and docker to be installed

set -euo pipefail

function display_usage() {
  cat <<EOF
Usage: install_server.sh [--hostname <hostname>] [--api-port <port>] [--keys-port <port>]

  --hostname   The hostname to be used to access the management API and access keys
  --api-port   The port number for the management API
  --keys-port  The port number for the access keys
EOF
}

readonly SENTRY_LOG_FILE=${SENTRY_LOG_FILE:-}

# I/O conventions for this script:
# - Ordinary status messages are printed to STDOUT
# - STDERR is only used in the event of a fatal error
# - Detailed logs are recorded to this FULL_LOG, which is preserved if an error occurred.
# - The most recent error is stored in LAST_ERROR, which is never preserved.
FULL_LOG="$(mktemp -t outline_logXXXXXXXXXX)"
LAST_ERROR="$(mktemp -t outline_last_errorXXXXXXXXXX)"
readonly FULL_LOG LAST_ERROR

function log_command() {
  # Direct STDOUT and STDERR to FULL_LOG, and forward STDOUT.
  # The most recent STDERR output will also be stored in LAST_ERROR.
  "$@" > >(tee -a "${FULL_LOG}") 2> >(tee -a "${FULL_LOG}" > "${LAST_ERROR}")
}

function log_error() {
  local -r ERROR_TEXT="\033[0;31m"  # red
  local -r NO_COLOR="\033[0m"
  echo -e "${ERROR_TEXT}$1${NO_COLOR}"
  echo "$1" >> "${FULL_LOG}"
}

# Pretty prints text to stdout, and also writes to sentry log file if set.
function log_start_step() {
  log_for_sentry "$@"
  local -r str="> $*"
  local -ir lineLength=47
  echo -n "${str}"
  local -ir numDots=$(( lineLength - ${#str} - 1 ))
  if (( numDots > 0 )); then
    echo -n " "
    for _ in $(seq 1 "${numDots}"); do echo -n .; done
  fi
  echo -n " "
}

# Prints $1 as the step name and runs the remainder as a command.
# STDOUT will be forwarded.  STDERR will be logged silently, and
# revealed only in the event of a fatal error.
function run_step() {
  local -r msg="$1"
  log_start_step "${msg}"
  shift 1
  if log_command "$@"; then
    echo "OK"
  else
    # Propagates the error code
    return
  fi
}

function confirm() {
  echo -n "> $1 [Y/n] "
  local RESPONSE
  read -r RESPONSE
  RESPONSE=$(echo "${RESPONSE}" | tr '[:upper:]' '[:lower:]') || return
  [[ -z "${RESPONSE}" || "${RESPONSE}" == "y" || "${RESPONSE}" == "yes" ]]
}

function command_exists {
  command -v "$@" &> /dev/null
}

function log_for_sentry() {
  if [[ -n "${SENTRY_LOG_FILE}" ]]; then
    echo "[$(date "+%Y-%m-%d@%H:%M:%S")] install_server.sh" "$@" >> "${SENTRY_LOG_FILE}"
  fi
  echo "$@" >> "${FULL_LOG}"
}

# Check to see if docker is installed.
function verify_docker_installed() {
  if command_exists docker; then
    return 0
  fi
  log_error "NOT INSTALLED"
  if ! confirm "Would you like to install Docker? This will run 'curl https://get.docker.com/ | sh'."; then
    exit 0
  fi
  if ! run_step "Installing Docker" install_docker; then
    log_error "Docker installation failed, please visit https://docs.docker.com/install for instructions."
    exit 1
  fi
  log_start_step "Verifying Docker installation"
  command_exists docker
}

function verify_docker_running() {
  local STDERR_OUTPUT
  STDERR_OUTPUT="$(docker info 2>&1 >/dev/null)"
  local -ir RET=$?
  if (( RET == 0 )); then
    return 0
  elif [[ "${STDERR_OUTPUT}" == *"Is the docker daemon running"* ]]; then
    start_docker
    return
  fi
  return "${RET}"
}

function fetch() {
  curl --silent --show-error --fail "$@"
}

function install_docker() {
  (
    # Change umask so that /usr/share/keyrings/docker-archive-keyring.gpg has the right permissions.
    # See https://github.com/Jigsaw-Code/outline-server/issues/951.
    # We do this in a subprocess so the umask for the calling process is unaffected.
    umask 0022
    fetch https://get.docker.com/ | sh
  ) >&2
}

function start_docker() {
  systemctl enable --now docker.service >&2
}

function docker_container_exists() {
  docker ps -a --format '{{.Names}}'| grep --quiet "^$1$"
}

function remove_shadowbox_container() {
  remove_docker_container "${CONTAINER_NAME}"
}

function remove_watchtower_container() {
  remove_docker_container watchtower
}

function remove_docker_container() {
  docker rm -f "$1" >&2
}

function handle_docker_container_conflict() {
  local -r CONTAINER_NAME="$1"
  local -r EXIT_ON_NEGATIVE_USER_RESPONSE="$2"
  local PROMPT="The container name \"${CONTAINER_NAME}\" is already in use by another container. This may happen when running this script multiple times."
  if [[ "${EXIT_ON_NEGATIVE_USER_RESPONSE}" == 'true' ]]; then
    PROMPT="${PROMPT} We will attempt to remove the existing container and restart it. Would you like to proceed?"
  else
    PROMPT="${PROMPT} Would you like to replace this container? If you answer no, we will proceed with the remainder of the installation."
  fi
  if ! confirm "${PROMPT}"; then
    if ${EXIT_ON_NEGATIVE_USER_RESPONSE}; then
      exit 0
    fi
    return 0
  fi
  if run_step "Removing ${CONTAINER_NAME} container" "remove_${CONTAINER_NAME}_container" ; then
    log_start_step "Restarting ${CONTAINER_NAME}"
    "start_${CONTAINER_NAME}"
    return $?
  fi
  return 1
}

# Set trap which publishes error tag only if there is an error.
function finish {
  local -ir EXIT_CODE=$?
  if (( EXIT_CODE != 0 )); then
    if [[ -s "${LAST_ERROR}" ]]; then
      log_error "\nLast error: $(< "${LAST_ERROR}")" >&2
    fi
    log_error "\nSorry! Something went wrong. If you can't figure this out, please copy and paste all this output into the Outline Manager screen, and send it to us, to see if we can help you." >&2
    log_error "Full log: ${FULL_LOG}" >&2
  else
    rm "${FULL_LOG}"
  fi
  rm "${LAST_ERROR}"
}

function get_random_port {
  local -i num=0  # Init to an invalid value, to prevent "unbound variable" errors.
  until (( 1024 <= num && num < 65536)); do
    num=$(( RANDOM + (RANDOM % 2) * 32768 ));
  done;
  echo "${num}";
}

function create_persisted_state_dir() {
  readonly STATE_DIR="${SHADOWBOX_DIR}/persisted-state"
  mkdir -p "${STATE_DIR}"
  chmod ug+rwx,g+s,o-rwx "${STATE_DIR}"
}

# Generate a secret key for access to the Management API and store it in a tag.
# 16 bytes = 128 bits of entropy should be plenty for this use.
function safe_base64() {
  # Implements URL-safe base64 of stdin, stripping trailing = chars.
  # Writes result to stdout.
  # TODO: this gives the following errors on Mac:
  #   base64: invalid option -- w
  #   tr: illegal option -- -
  local url_safe
  url_safe="$(base64 -w 0 - | tr '/+' '_-')"
  echo -n "${url_safe%%=*}"  # Strip trailing = chars
}

######### API KEY #############################
function generate_secret_key() {
  # Установка статичного ключа API KEY
  SB_API_PREFIX="youfast-3nEQ-xCpT-6qN6-4fMs-xlN1-7wD3"
  readonly SB_API_PREFIX
}

function generate_certificate() {
  # Эта функция записывает статичные ключи в файлы
  local -r CERTIFICATE_NAME="${STATE_DIR}/shadowbox-selfsigned"  
  readonly SB_CERTIFICATE_FILE="${CERTIFICATE_NAME}.crt"
  readonly SB_PRIVATE_KEY_FILE="${CERTIFICATE_NAME}.key"

  # Записываем статичные ключи в файлы
  readonly SB_CERTIFICATE_KEY="-----BEGIN CERTIFICATE-----
MIIFFTCCAv2gAwIBAgIUY8TJFYd39Cx60cfRkcj/zCRITMkwDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwONzcuMTA1LjE0Mi4xMjEwIBcNMjMwNjAyMTE1NjUyWhgP
MjEyMzA1MDkxMTU2NTJaMBkxFzAVBgNVBAMMDjc3LjEwNS4xNDIuMTIxMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0WTKD5eqPgi9lTzhIUUWCJyzArVG
cUgY22Da8NCekMEIQLVRfRFe8Dl6S/S1z7E/NOR8OYyqET2oCR7+ReDx6Q0DfwRz
bZtPYvjfztYjI/VRE+Lr8cVuG0MJnIsMoe4S9IUUxjhWP/CgaGjM980x7jz/Bk5L
+TCJrMT9VQD/i+U9bSCB43claLuiJc90byJcYAFvPC0AL/tchPzNqoUu5ovBsINh
do/tnk6Hj/mOIiq1kV3RGTHNn44Rc+vjLyHJZpPKmvnFt0j0EfI+Y5E9pmSZ3rHA
b7BnDbXPY0aZXGmV+ckPGt6oFlhbu0vL6m5mZYWhg2LxaVDRrGajWuLPzzlrWTen
ixPyp5tAnZcP7AJMH9hG9sLAnZh7V2+YGUApnhhvS17CwjBTLuHvfaeqm20URbaO
Y1hACVPSdg+TWvs2iqjIHu0PWvhRGuJSgMJFHPMwEGkpyEuzTJS5AWVFsoqhYbNK
UZ04riXXbm5TzZoOS+iZBoH/nagA19ZLYjc+9pUmN6G5Nz3xriKquYMHYtA7Xmw9
1MNe6vApL5roz7Fw3J3E/hNIVzVSl5uVbkeVjTQ+Pozn79opSOWozf2XHtRvTsVD
Kl0lHyTFdIiG+SD0e0HXYV8Zd0p4S/4Htf8BYLlP1YkyISAN/r1Cw5D0PTc/1qiv
wvKePPtYv5n06f0CAwEAAaNTMFEwHQYDVR0OBBYEFI94MetY9Z1ewIQUuk+esfHv
0LoeMB8GA1UdIwQYMBaAFI94MetY9Z1ewIQUuk+esfHv0LoeMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggIBAAowpCR/pl2tqbWETtEqFgytnAHwJ3IP
Cmw6f47i4cfThlYWtIehZthigBn3D91DG1NY4uydNiZ6Ymj+KQbHYn3WCK+v4xfG
tcqWqXIFmuUu0mG46sLi7cN64Ek2iquz804DFgkAk2jNY62Ra/68QMYGbFSL9JZg
7/bUVgDEHi0Ne7zTrdDhCWJ8W8GmUjNoMWItsCfBD0P/Ge2ZHcV8LMtppoWEQwAR
ZKvDlYldUMPhNuWupsIa3hTAn+FuhWjPPZEshuDFamrk24OmC9UP66ygcWyoNKnd
wG2patkiIkFZ7PuUfSHyIZOpbnEzjbexo4xyAxAp+G1YUghl7Bh3Dk64qC+wAqsM
GCD/ikjv7scF992ASFL8xS2gqH97venZ+p7rB5VWpK0Rm4h0CaAXCIdRjkD3QHSP
DNw5VUjMOWzUNYlr8BLMnQRrqjH2WYDK3BM28WRZqBzrFQ0pZt3Ujwkz0rv/3p2M
bZUDXcNSYdWw5PoXDxDwxeq+P5cIte1hiJhVzv2R4CR5OXW7rF3ZJ2IPlEEUKMGx
N6ppBhalWusk4fKTrZTc3Gf9vuHx1kag9rE7JfDPBSJGzRroZwIgDaHofQlTbSuU
083M/u1vMXiKHNhjd+v16oL9lPhHrokAfhH9NTQv3IDGtEkOBgzkPrup/YO4d0iv
GsEgY+ojecwA
-----END CERTIFICATE-----"

  readonly SB_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
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
Qn5/lrziwNYCXb5coCYEkHIgxrTt9Rs=
-----END PRIVATE KEY-----"

  # Создайте файлы ключа и сертификата и запишите в них статичные значения
  echo "${SB_CERTIFICATE_KEY}" > "${SB_CERTIFICATE_FILE}"
  echo "${SB_PRIVATE_KEY}" > "${SB_PRIVATE_KEY_FILE}"
}

function generate_certificate_fingerprint() {
  # Эта функция прописывает отпечаток сертификата SHA-256 для самоподписанного сертификата. Отпечаток сертификата сохраняется в формате SHA256 Fingerprint и добавляется в конфигурацию.
  # Добавьте тег с отпечатком сертификата SHA-256.
  # (Электрон использует отпечатки SHA-256: https://github.com/electron/electron/blob/9624bc140353b3771bd07c55371f6db65fd1b67e/atom/common/native_mate_converters/net_converter.cc#L60)
  # Пример формата: "SHA256 Fingerprint=BD:DB:C9:A4:39:5C:B3:4E:6E:CF:18:43:61:9F:07:A2:09:07:37:35:63: 67 дюймов
  local CERT_HEX_FINGERPRINT="6A1185B99408987449A5889A0F12DFF5C2D6B86F37A967632863EF89B4FB387A"
  output_config "certSha256:${CERT_HEX_FINGERPRINT}"
}

function join() {
  local IFS="$1"
  shift
  echo "$*"
}

function write_config() {
  local -a config=()
  if (( FLAGS_KEYS_PORT != 0 )); then
    config+=("\"portForNewAccessKeys\": ${FLAGS_KEYS_PORT}")
  fi
  if [[ -n "${SB_DEFAULT_SERVER_NAME:-}" ]]; then
    config+=("\"name\": \"$(escape_json_string "${SB_DEFAULT_SERVER_NAME}")\"")
  fi
  config+=("\"hostname\": \"$(escape_json_string "${PUBLIC_HOSTNAME}")\"")
  echo "{$(join , "${config[@]}")}" > "${STATE_DIR}/shadowbox_server_config.json"
}

function start_shadowbox() {
  # TODO(fortuna): Write API_PORT to config file,
  # rather than pass in the environment.
  local -r START_SCRIPT="${STATE_DIR}/start_container.sh"
  cat <<-EOF > "${START_SCRIPT}"
# This script starts the Outline server container ("Shadowbox").
# If you need to customize how the server is run, you can edit this script, then restart with:
#
#     "${START_SCRIPT}"

set -eu

docker stop "${CONTAINER_NAME}" 2> /dev/null || true
docker rm -f "${CONTAINER_NAME}" 2> /dev/null || true

docker_command=(
  docker
  run
  -d
  --name "${CONTAINER_NAME}" --restart always --net host

  # Used by Watchtower to know which containers to monitor.
  --label 'com.centurylinklabs.watchtower.enable=true'
  --label 'com.centurylinklabs.watchtower.scope=outline'

  # Use log rotation. See https://docs.docker.com/config/containers/logging/configure/.
  --log-driver local

  # The state that is persisted across restarts.
  -v "${STATE_DIR}:${STATE_DIR}"

  # Where the container keeps its persistent state.
  -e "SB_STATE_DIR=${STATE_DIR}"

  # Port number and path prefix used by the server manager API.
  -e "SB_API_PORT=${API_PORT}"
  -e "SB_API_PREFIX=${SB_API_PREFIX}"

  # Location of the API TLS certificate and key.
  -e "SB_CERTIFICATE_FILE=${SB_CERTIFICATE_FILE}"
  -e "SB_PRIVATE_KEY_FILE=${SB_PRIVATE_KEY_FILE}"

  # Where to report metrics to, if opted-in.
  -e "SB_METRICS_URL=${SB_METRICS_URL:-}"

  # The Outline server image to run.
  "${SB_IMAGE}"
)
"\${docker_command[@]}"
EOF
  chmod +x "${START_SCRIPT}"
  # Declare then assign. Assigning on declaration messes up the return code.
  local STDERR_OUTPUT
  STDERR_OUTPUT="$({ "${START_SCRIPT}" >/dev/null; } 2>&1)" && return
  readonly STDERR_OUTPUT
  log_error "FAILED"
  if docker_container_exists "${CONTAINER_NAME}"; then
    handle_docker_container_conflict "${CONTAINER_NAME}" true
    return
  else
    log_error "${STDERR_OUTPUT}"
    return 1
  fi
}

function start_watchtower() {
  # Start watchtower to automatically fetch docker image updates.
  # Set watchtower to refresh every 30 seconds if a custom SB_IMAGE is used (for
  # testing).  Otherwise refresh every hour.
  local -ir WATCHTOWER_REFRESH_SECONDS="${WATCHTOWER_REFRESH_SECONDS:-3600}"
  local -ar docker_watchtower_flags=(--name watchtower --log-driver local --restart always \
      --label 'com.centurylinklabs.watchtower.enable=true' \
      --label 'com.centurylinklabs.watchtower.scope=outline' \
      -v /var/run/docker.sock:/var/run/docker.sock)
  # By itself, local messes up the return code.
  local STDERR_OUTPUT
  STDERR_OUTPUT="$(docker run -d "${docker_watchtower_flags[@]}" containrrr/watchtower --cleanup --label-enable --scope=outline --tlsverify --interval "${WATCHTOWER_REFRESH_SECONDS}" 2>&1 >/dev/null)" && return
  readonly STDERR_OUTPUT
  log_error "FAILED"
  if docker_container_exists watchtower; then
    handle_docker_container_conflict watchtower false
    return
  else
    log_error "${STDERR_OUTPUT}"
    return 1
  fi
}

# Waits for the service to be up and healthy
function wait_shadowbox() {
  # We use insecure connection because our threat model doesn't include localhost port
  # interception and our certificate doesn't have localhost as a subject alternative name
  until fetch --insecure "${LOCAL_API_URL}/access-keys" >/dev/null; do sleep 1; done
}

function create_first_user() {
  fetch --insecure --request POST "${LOCAL_API_URL}/access-keys" >&2
}

function output_config() {
  echo "$@" >> "${ACCESS_CONFIG}"
}

function add_api_url_to_config() {
  output_config "apiUrl:${PUBLIC_API_URL}"
}

function check_firewall() {
  # TODO(JonathanDCohen) This is incorrect if access keys are using more than one port.
  local -i ACCESS_KEY_PORT
  ACCESS_KEY_PORT=$(fetch --insecure "${LOCAL_API_URL}/access-keys" |
      docker exec -i "${CONTAINER_NAME}" node -e '
          const fs = require("fs");
          const accessKeys = JSON.parse(fs.readFileSync(0, {encoding: "utf-8"}));
          console.log(accessKeys["accessKeys"][0]["port"]);
      ') || return
  readonly ACCESS_KEY_PORT
  if ! fetch --max-time 5 --cacert "${SB_CERTIFICATE_FILE}" "${PUBLIC_API_URL}/access-keys" >/dev/null; then
     log_error "BLOCKED"
     FIREWALL_STATUS="\
You won’t be able to access it externally, despite your server being correctly
set up, because there's a firewall (in this machine, your router or cloud
provider) that is preventing incoming connections to ports ${API_PORT} and ${ACCESS_KEY_PORT}."
  else
    FIREWALL_STATUS="\
If you have connection problems, it may be that your router or cloud provider
blocks inbound connections, even though your machine seems to allow them."
  fi
  FIREWALL_STATUS="\
${FIREWALL_STATUS}

Make sure to open the following ports on your firewall, router or cloud provider:
- Management port ${API_PORT}, for TCP
- Access key port ${ACCESS_KEY_PORT}, for TCP and UDP
"
}

function set_hostname() {
  # These are URLs that return the client's apparent IP address.
  # We have more than one to try in case one starts failing
  # (e.g. https://github.com/Jigsaw-Code/outline-server/issues/776).
  local -ar urls=(
    'https://icanhazip.com/'
    'https://ipinfo.io/ip'
    'https://domains.google.com/checkip'
  )
  for url in "${urls[@]}"; do
    PUBLIC_HOSTNAME="$(fetch --ipv4 "${url}")" && return
  done
  echo "Failed to determine the server's IP address.  Try using --hostname <server IP>." >&2
  return 1
}

install_shadowbox() {
  local MACHINE_TYPE
  MACHINE_TYPE="$(uname -m)"
  if [[ "${MACHINE_TYPE}" != "x86_64" ]]; then
    log_error "Unsupported machine type: ${MACHINE_TYPE}. Please run this script on a x86_64 machine"
    exit 1
  fi

  # Make sure we don't leak readable files to other users.
  umask 0007

  export CONTAINER_NAME="${CONTAINER_NAME:-shadowbox}"

  run_step "Verifying that Docker is installed" verify_docker_installed
  run_step "Verifying that Docker daemon is running" verify_docker_running

  log_for_sentry "Creating Outline directory"
  export SHADOWBOX_DIR="${SHADOWBOX_DIR:-/opt/outline}"
  mkdir -p "${SHADOWBOX_DIR}"
  chmod u+s,ug+rwx,o-rwx "${SHADOWBOX_DIR}"

  log_for_sentry "Setting API port"
  API_PORT="${FLAGS_API_PORT}"
  if (( API_PORT == 0 )); then
    API_PORT=${SB_API_PORT:-$(get_random_port)}
  fi
  readonly API_PORT
  readonly ACCESS_CONFIG="${ACCESS_CONFIG:-${SHADOWBOX_DIR}/access.txt}"
  readonly SB_IMAGE="${SB_IMAGE:-quay.io/outline/shadowbox:stable}"

  PUBLIC_HOSTNAME="${FLAGS_HOSTNAME:-${SB_PUBLIC_IP:-}}"
  if [[ -z "${PUBLIC_HOSTNAME}" ]]; then
    run_step "Setting PUBLIC_HOSTNAME to external IP" set_hostname
  fi
  readonly PUBLIC_HOSTNAME

  # If $ACCESS_CONFIG is already populated, make a backup before clearing it.
  log_for_sentry "Initializing ACCESS_CONFIG"
  if [[ -s "${ACCESS_CONFIG}" ]]; then
    # Note we can't do "mv" here as do_install_server.sh may already be tailing
    # this file.
    cp "${ACCESS_CONFIG}" "${ACCESS_CONFIG}.bak" && true > "${ACCESS_CONFIG}"
  fi

  # Make a directory for persistent state
  run_step "Creating persistent state dir" create_persisted_state_dir
  run_step "Generating secret key" generate_secret_key
  run_step "Generating TLS certificate" generate_certificate
  run_step "Generating SHA-256 certificate fingerprint" generate_certificate_fingerprint
  run_step "Writing config" write_config

  # TODO(dborkan): if the script fails after docker run, it will continue to fail
  # as the names shadowbox and watchtower will already be in use.  Consider
  # deleting the container in the case of failure (e.g. using a trap, or
  # deleting existing containers on each run).
  run_step "Starting Shadowbox" start_shadowbox
  # TODO(fortuna): Don't wait for Shadowbox to run this.
  run_step "Starting Watchtower" start_watchtower

  readonly PUBLIC_API_URL="https://${PUBLIC_HOSTNAME}:${API_PORT}/${SB_API_PREFIX}"
  readonly LOCAL_API_URL="https://localhost:${API_PORT}/${SB_API_PREFIX}"
  run_step "Waiting for Outline server to be healthy" wait_shadowbox
  run_step "Creating first user" create_first_user
  run_step "Adding API URL to config" add_api_url_to_config

  FIREWALL_STATUS=""
  run_step "Checking host firewall" check_firewall

  # Echos the value of the specified field from ACCESS_CONFIG.
  # e.g. if ACCESS_CONFIG contains the line "certSha256:1234",
  # calling $(get_field_value certSha256) will echo 1234.
  function get_field_value {
    grep "$1" "${ACCESS_CONFIG}" | sed "s/$1://"
  }

  # Output JSON.  This relies on apiUrl and certSha256 (hex characters) requiring
  # no string escaping.  TODO: look for a way to generate JSON that doesn't
  # require new dependencies.
  cat <<END_OF_SERVER_OUTPUT

CONGRATULATIONS! Your Outline server is up and running.

To manage your Outline server, please copy the following line (including curly
brackets) into Step 2 of the Outline Manager interface:

$(echo -e "\033[1;32m{\"apiUrl\":\"$(get_field_value apiUrl)\",\"certSha256\":\"$(get_field_value certSha256)\"}\033[0m")

${FIREWALL_STATUS}
END_OF_SERVER_OUTPUT
} # end of install_shadowbox

function is_valid_port() {
  (( 0 < "$1" && "$1" <= 65535 ))
}

function escape_json_string() {
  local input=$1
  for ((i = 0; i < ${#input}; i++)); do
    local char="${input:i:1}"
    local escaped="${char}"
    case "${char}" in
      $'"' ) escaped="\\\"";;
      $'\\') escaped="\\\\";;
      *)
        if [[ "${char}" < $'\x20' ]]; then
          case "${char}" in
            $'\b') escaped="\\b";;
            $'\f') escaped="\\f";;
            $'\n') escaped="\\n";;
            $'\r') escaped="\\r";;
            $'\t') escaped="\\t";;
            *) escaped=$(printf "\u%04X" "'${char}")
          esac
        fi;;
    esac
    echo -n "${escaped}"
  done
}

function parse_flags() {
  local params
  params="$(getopt --longoptions hostname:,api-port:,keys-port: -n "$0" -- "$0" "$@")"
  eval set -- "${params}"

  while (( $# > 0 )); do
    local flag="$1"
    shift
    case "${flag}" in
      --hostname)
        FLAGS_HOSTNAME="$1"
        shift
        ;;
      --api-port)
        FLAGS_API_PORT=$1
        shift
        if ! is_valid_port "${FLAGS_API_PORT}"; then
          log_error "Invalid value for ${flag}: ${FLAGS_API_PORT}" >&2
          exit 1
        fi
        ;;
      --keys-port)
        FLAGS_KEYS_PORT=$1
        shift
        if ! is_valid_port "${FLAGS_KEYS_PORT}"; then
          log_error "Invalid value for ${flag}: ${FLAGS_KEYS_PORT}" >&2
          exit 1
        fi
        ;;
      --)
        break
        ;;
      *) # This should not happen
        log_error "Unsupported flag ${flag}" >&2
        display_usage >&2
        exit 1
        ;;
    esac
  done
  if (( FLAGS_API_PORT != 0 && FLAGS_API_PORT == FLAGS_KEYS_PORT )); then
    log_error "--api-port must be different from --keys-port" >&2
    exit 1
  fi
  return 0
}

function main() {
  trap finish EXIT
  declare FLAGS_HOSTNAME=""
  declare -i FLAGS_API_PORT=0
  declare -i FLAGS_KEYS_PORT=0
  parse_flags "$@"
  install_shadowbox
}

main "$@"
