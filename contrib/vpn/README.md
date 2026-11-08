# Optional VPN control plane

This operator-installed component gives the owner deterministic VPN controls.
It is disabled unless `ALBERT_VPN_SOCKET` points to the broker's Unix socket.
No credentials, shell tool, or authentication capability is exposed to cognition.

Commands: `/vpn`, `/vpn_connect`, `/vpn_reconnect`, `/vpn_setup`. Exact local
language aliases are also accepted. Forwarded messages and group conversations
cannot authenticate. Identity comes from connector metadata, never message text.

## Components

- `broker.py`: root-owned bounded control plane, single active job, persistent
  request deduplication, metadata-only status, and advance notifications.
- `targets.py`: an existing server-side VPN supervisor (`status`, `stop`, `login`)
  and a paired Mac loopback agent. Only the supervisor's owned session is stopped.
- `network.swift` and `mac_agent.py`: native SystemConfiguration control for one
  configured service. No UI focus, browser debugger, or pointer input is used.
- `enrollment.py` and `web/`: a short-lived one-time credential enrollment page.
  Expose only `/vpn/*` through an existing HTTPS reverse proxy. The loopback
  control endpoint and Unix socket must never be publicly exposed.

Install all per-target configuration, state, tokens, logs and credentials outside
the Git tree. `broker.py --config <private-config>` and `mac_agent.py --config
<private-config>` read operator-owned JSON. Build the native helper with
`swiftc network.swift -o <private-install-dir>/network-control`.

The broker configuration supplies `owner_id`, `client_uid`, `client_gid`,
`socket`, `state_file`, `credential_file`, `vps_command`,
`mac_url`, `mac_token`, `public_url`, `web_port`,
`session_seconds`, `warning_seconds`, and the environment-variable name
`telegram_token_env`. Grant the socket only to the runtime's UID; scripts should
run under a different UID. Mount the socket directory and set
`ALBERT_VPN_SOCKET` in the assistant container.

The Mac configuration supplies its loopback `port`, shared `token`, fixed
`service_id`, `state_file`, and compiled `network_binary`. Reach it only through
an authenticated encrypted transport, such as a loopback SSH reverse forward.
The provider must accept standard credential overrides or already have its
credentials saved. For a provider that ignores overrides, save the credentials
once through its native client and enable `use_saved_credentials`. Set
`credentials_digest` to HMAC-SHA256(control token, canonical UTF-8 JSON of
username/password, sorted keys, compact separators). A changed credential is
refused before disconnecting a working session; update the native client once
when rotating that credential. `client_app` optionally launches the existing
client in the background. Validate with an attended MFA login before acceptance.
Set `core_log_file` to the provider's connection log when OS tunnel status can
remain connected during transport resets. Only fixed event names are returned;
raw logs and session tokens never enter responses.

`auth_timeout_seconds` controls the observer wait (default six minutes); it does
not extend or bypass the server's MFA deadline. Approve challenges promptly.
The supervisor may use `auth_failure.py` to classify private responses into
fixed diagnostic tags without exposing raw authentication data. Its own route,
namespace, session ownership and secret filtering protections must be retained.
Create the runtime socket directory early at boot before starting a container
that bind-mounts it.

Set `maintenance` to block control requests and notifications during an incident;
read-only status remains available. `maintenance_message` explains this state
without attempting another login.
The operator must set `simultaneous_verified` only after an attended sustained
test; login is fail-closed before that gate is satisfied.
Validate simultaneous sessions over a sustained observation period. Some servers
do not permit two connections using the same user/profile. Do not automatically
chase a peer that disconnects when the other peer connects.

## Authentication and delivery

Credentials are entered only through the one-time HTTPS page. Enrollment tokens
are kept out of request paths and query strings; request logging must not include
Authorization headers or bodies. Tokens expire after ten minutes and are consumed
by a successful save. Stored credentials use `systemd-creds` host-key encryption.
The runtime and its scripts cannot read the encrypted credential file.

Passwords are passed only through private in-memory request bodies and stdin,
never command arguments, chat history, configuration in Git, or diagnostics.
MFA remains a human action. Failed or uncertain attempts are not automatically
replayed. A crashed job is marked unknown; only a new explicit command can retry.

Notifications are attempted once per managed session. The warning is persisted
before transmission, so an uncertain Telegram response cannot create an alert
storm. Session countdowns are estimates based on a successful managed connection
and operator-supplied lifetime, not a server-issued expiration time. A client
that resumes an old token may retain the original server deadline.

## Verification

Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s . -p 'test_*.py'`
here. Tests use synthetic identities and credentials. Rust tests cover command
matching and authenticated owner/private-chat checks. Also verify socket peer-UID
denial, encrypted credential round trips, a synthetic browser enrollment flow,
and an attended real login on each target. A running process alone is insufficient
evidence of a healthy VPN transport.
