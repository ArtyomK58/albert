# Dormant single-session gateway option

This option is prepared separately from the legacy dual-session controller. It is
off unless all operator-owned gates pass. Preparing source, configuration and a
rendered plan must not authenticate, stop a session, change routes or install DNS.

The intended topology terminates the client's personal VPN on a gateway host.
Only reviewed corporate prefixes from the configured peer are forwarded through
an isolated corporate VPN namespace. Ordinary Internet and management transport
retain their existing paths. Other peers, containers and public interfaces do not
gain corporate access.

## Configuration

The private broker configuration can contain:

```json
{
  "gateway_option": {
    "enabled": false,
    "prepare_only": true,
    "network_verified": false,
    "preferred_mode": "vps",
    "network_hook": [],
    "state_file": "<private-state-directory>/mode.json",
    "verify_seconds": 60
  }
}
```

Keep the live broker and client maintenance gates until attended acceptance.
The staged Mac config additionally sets `mode_epoch_required: true`. This is not
applied to an existing client until the operator deploys this version.

`/vpn_mode` reports readiness; `/vpn_vps`, `/vpn_mac` and exact mode aliases select
one session. Disabled requests return before credentials, target calls or state
files are touched. In single-session mode legacy connect/reconnect commands cannot
enter the dual-session path. Commands remain authenticated owner/private-chat
reflexes outside the LLM.

`modes.py` serializes switches with an OS file lock, stores an epoch and request
deduplication, confirms the old session is down before starting the new one, waits
at least a minute for retained transport, then runs network acceptance. Interrupted
or uncertain switches require operator reconciliation. There is no automatic MFA
retry or login rollback. Mac rejects stale epochs before invoking its native helper.

## Network preparation and activation boundary

`gateway_plan.py --config <private-network-spec>` only validates and renders JSON.
It has no command runner. Store its output outside the repository. It describes
dedicated firewall chains, source-based routing, unreachable fallback routes,
container NAT exemptions, namespace forwarding/SNAT, MSS and staged split-DNS data.
It rejects default routes, unmanaged public prefixes, interface-name injection and
overlap with protected local/management networks. Public push routes need a
separate review rather than silent import.

The renderer is a review artifact, not an executable deployment or rollback script.
`gateway_hook.py` and `gateway_mac.py` supply separately gated, operator-owned
network backends. Their manifests also default to disabled/preparation-only.
They are staged without installing the Mac privileged helper or running any
network phase. Until privileged installation and attended acceptance are complete,
`network_verified` must stay false. A successful render is not a working gateway.

The future hook accepts one JSON object on stdin with `phase` and `target`:
`preflight` checks control-channel reachability, current topology, peer isolation,
route ownership and supervisor reconnect policy; `block` is an idempotent
fail-closed withdrawal; `activate` installs exactly the reviewed target's routing
and DNS; `verify` checks real service/DNS access and leakage. It must return bounded
JSON with `ok`. The executable must be root-owned and not group/world writable.
The host backend updates only dedicated firewall chains with atomic restore,
retains unreachable fallback routes, verifies container identity and owns a
manifest signature. It exposes the peer only after the namespace and Mac are ready.
The Mac backend uses an existing Apple PF anchor, retains corporate blocking during
handover, records exact route/resolver ownership and rejects stale epochs. It never
rewrites pf.conf or disables another owner's PF. Installation requires root-owned
code/config and a narrowly scoped privileged invocation, not a password in the bot.
Apply and withdrawal use the current generation, not a replay of the rendered list.

`install_gateway_mac.py` is the separate attended root installation step. It
accepts disabled manifests only and stages a fixed-config isolated launcher with
a narrowly scoped sudo rule; it does not run PF, route, DNS or VPN commands.
Its launcher accepts only the enumerated phase/target and an integer epoch, never
an alternate configuration path or a shell command. Preparing this installer does
not authorize running it or requesting an administrator prompt.

Activation still requires a controlled MFA cycle, split-DNS/fallback/IPv6 tests,
another-peer denial, namespace recreation, route collision checks and a latency
comparison. Any private supervisor code that can restore global forwarding to zero
must be addressed during that separately authorized deployment. Do not change the
personal VPN container's lifecycle or reconnect policy merely to prepare this option.

## Tests

Run the existing Python suite plus `test_gateway.py`. Synthetic tests cover disabled
side-effect freedom, route rejection, stop-confirm-start order, uncertain-outcome
freeze and stale Mac epochs. Build/test the Rust command reflexes and compile the
native helper without executing it. No live login is part of preparation.
