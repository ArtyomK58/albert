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
one session; `/vpn_recover` withdraws the gateway's own network changes (see below).
Disabled requests return before credentials, target calls or state files are touched. In single-session mode legacy connect/reconnect commands cannot
enter the dual-session path. Commands remain authenticated owner/private-chat
reflexes outside the LLM.

`modes.py` serializes switches with an OS file lock, stores an epoch and request
deduplication, confirms the old session is down before starting the new one, waits
at least a minute for retained transport, then runs network acceptance. Interrupted
or uncertain switches require operator reconciliation. There is no automatic MFA
retry or login rollback. Mac rejects stale epochs before invoking its native helper; its high-water mark is
stored separately from the bounded result cache and survives restarts.

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
and DNS; `verify` checks that the corporate routes use the expected interface and
that one probe service resolves into a corporate prefix and accepts TCP. `verify`
does not prove the absence of DNS or IPv6 leaks; those remain separate attended
acceptance tests. `recover` is described below. It must return bounded JSON with `ok`. The executable must be root-owned and not group/world writable.
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

## Recovery (owned off-ramp)

A failed or uncertain switch freezes new logins and can leave the fail-closed block
in place, including on the client's native corporate VPN. `/vpn_recover` (owner,
private chat) or, as root on the gateway host, `modes.py --config <broker-config>
--recover` withdraws only the gateway's own network changes:

- it never authenticates, starts MFA, stops or starts a VPN session, or enables
  the gateway; afterwards the next login needs a new explicit command;
- it works while the option is disabled or under maintenance, but only when a
  switch state file exists; otherwise it returns `nothing_to_recover` without
  creating files or running the hook;
- it takes a new epoch first, so a delayed apply from an older switch is rejected;
- the host withdraws the peer first, then removes the recorded container NAT
  exemption, exact policy rules, exact table routes, the owned `/32` return route
  and namespace chains/routes, and removes its own firewall chain last. Global
  forwarding, Docker's shared chains, default routes and foreign entries with the
  same priority or table are retained;
- a kernel rule delete ignores selectors the request omits, so a policy rule is
  deleted only when it is the single candidate for that request and matches the
  attributes recorded at creation. Any other candidate (an extra selector such as
  fwmark or uidrange, or another protocol) leaves every candidate in place and
  reports operator reconciliation; activation likewise never deletes and re-adds;
- the client removes only recorded routes that still point at the recorded
  interface, resolver files whose content is unchanged, the rules and tables of
  its own PF anchor (refusing if the anchor holds foreign rules), and releases its
  own PF enable reference. It never disables PF or edits `pf.conf`;
- each resource is recorded before creation; withdrawal uses the recorded
  generation, not the current configuration. A foreign change is kept and reported.

If the client is unreachable, the host keeps the peer blocked and reports
`recovery_incomplete`; logins stay frozen and recovery can be repeated. An
unreadable or malformed switch state file is never rewritten: status, switching
and recovery report operator reconciliation without touching credentials,
sessions or the network.

A configured mode is not an active gateway. Status reports whether the last
switch left the gateway applied. After recovery, `/vpn_vps` or `/vpn_mac` re-applies
the gateway network for a session that is already healthy on that host while the
other host is down: it takes a new epoch and runs preflight, block, activate and
verify, with no stop, login, credentials or MFA. Otherwise it performs a normal
switch. Forced reauthentication remains the explicit reconnect command. When the
gateway host itself is unavailable, the client operator can run the installed
launcher with `--phase recover --target mac --epoch <current mode epoch>`.
These withdrawal semantics are verified only on simulated hosts; PF anchor flush
and reference release must be confirmed during attended client acceptance.

## Bounded waits

Every layer has an absolute budget and starts a step only when that step's full
timeout plus a fail-safe reserve still fits, so an outer layer never kills an
inner step that is still within its allowance. Budgets are fixed in
`gateway_plan.py`: client OS command < client helper phase < relay exec limit <
relay call including endpoint probes < host hook phase < broker wait for the hook.
The relay command in the private hook configuration must use the exact relay exec
limit; otherwise the hook refuses before dispatching. Lock waits are bounded. An
expired budget is reported as a failure after re-blocking; nothing is retried
automatically and no MFA is repeated.

## Acceptance

Activation still requires a controlled MFA cycle, split-DNS/fallback/IPv6 tests,
another-peer denial, namespace recreation, route collision checks and a latency
comparison. Any private supervisor code that can restore global forwarding to zero
must be addressed during that separately authorized deployment. Do not change the
personal VPN container's lifecycle or reconnect policy merely to prepare this option.

## Tests

Run the existing Python suite plus `test_gateway.py`, `test_gateway_network.py` and
`test_gateway_recovery.py` and `test_gateway_budget.py` (simulators in
`gateway_fakes.py`). Synthetic tests cover disabled side-effect freedom, route
rejection, stop-confirm-start order, uncertain-outcome freeze, stale epochs across
cache eviction and restart, recovery after failure/timeout/disablement with foreign
state retained, bounded budgets and installer rollback. The recovery tests run the
real hook and helper entry points against simulated hosts; they are not a substitute
for attended acceptance on the real client and gateway. Build/test the Rust command reflexes and compile the
native helper without executing it. No live login is part of preparation.
## Overlay ingress

`transport: tailnet` selects a single CGNAT `/32` peer and verifies its configured
stable node ID against the live overlay status. The host return route remains
owned by the overlay. Docker NAT exemptions are not used in this mode.

The owned nftables guard runs before the overlay's forwarding accepts. Its
postrouting filter removes only the overlay NAT mark for the approved peer and
corporate destinations, preserving source identity inside the VPN namespace.
Shared overlay chains are never flushed or replaced. Recovery requires the
recorded semantic digest of the owned nftables table.

The Mac helper blocks corporate IPv4 and global/ULA IPv6 outside the selected
tunnel. Operator-owned scoped DNS must remain present during authentication and
network withdrawal. Native Mac mode is refused while this ingress configuration
is selected; changing exit-node ownership needs separate operator coordination.
Unit tests do not substitute for attended DNS, PF, MFA and real-device acceptance.

