"""Owned early nftables guard, evaluated before another overlay's filter accept."""
import hashlib
import json
from pathlib import Path


TABLE = 'frog_corp_guard'


def digest(value):
    def clean(x):
        if isinstance(x, dict):
            return {k: clean(v) for k, v in x.items() if k not in ('handle', 'metainfo')}
        if isinstance(x, list):
            return [clean(v) for v in x if not isinstance(v, dict) or 'metainfo' not in v]
        return x
    return hashlib.sha256(json.dumps(clean(value), sort_keys=True).encode()).hexdigest()


class TailnetGuard:
    def __init__(self, parent):
        self.parent = parent

    def receipt(self):
        path = self.parent.c.get('guard_state')
        value = (json.loads(Path(path).read_text()) if path and Path(path).exists()
                 else self.parent.owner() or {})
        if value and value.get('signature') != digest(self.parent.spec):
            raise RuntimeError('tailnet_guard_spec_requires_operator')
        return value

    def owned(self, current):
        return current is not None and digest(current) == self.receipt().get('tailnet_guard_digest')

    def save_receipt(self, value):
        owner = self.parent.owner()
        owner['tailnet_guard_digest'] = digest(value)
        self.parent.save_owner(owner)
        path = self.parent.c.get('guard_state')
        if path:
            path = Path(path)
            temp = path.with_suffix('.new')
            temp.write_text(json.dumps({'signature': digest(self.parent.spec),
                                        'tailnet_guard_digest': digest(value)}))
            temp.chmod(0o600)
            temp.replace(path)

    def inspect(self, reserve):
        r = self.parent.command(['nft', '-s', '-j', 'list', 'table', 'inet', TABLE], check=False, reserve=reserve)
        if r.returncode:
            if 'No such file' in r.stderr:
                return None
            raise RuntimeError('tailnet_guard_inspection_failed')
        return json.loads(r.stdout)

    def render(self, active, exists):
        s = self.parent.spec
        q = json.dumps
        rows = []
        if not exists:
            rows += ['add table inet ' + TABLE + ' { comment "owned corporate gateway guard"; }',
                     'add set inet ' + TABLE + ' corp4 { type ipv4_addr; flags interval; }',
                     'add chain inet ' + TABLE + ' forward { type filter hook forward priority -10; policy accept; }',
                     'add chain inet ' + TABLE + ' postrouting { type filter hook postrouting priority -10; policy accept; }']
        else:
            rows += ['flush chain inet ' + TABLE + ' forward',
                     'flush chain inet ' + TABLE + ' postrouting', 'flush set inet ' + TABLE + ' corp4']
        rows.append('add element inet ' + TABLE + ' corp4 { ' + ', '.join(s['corporate_prefixes']) + ' }')
        rules = ['oifname ' + q(s['host_veth']) + ' ip daddr ' + s['namespace_link_address']
                 + ' ct state established,related accept']
        if active:
            rules += ['iifname ' + q(s['host_bridge']) + ' oifname ' + q(s['host_veth'])
                      + ' ip saddr ' + s['mac_peer'] + ' ip daddr @corp4 accept',
                      'iifname ' + q(s['host_veth']) + ' oifname ' + q(s['host_bridge'])
                      + ' ip daddr ' + s['mac_peer'] + ' ct state established,related accept']
        rules += ['ip daddr @corp4 reject', 'oifname ' + q(s['host_veth']) + ' drop',
                  'iifname ' + q(s['host_veth']) + ' oifname ' + q(s['host_bridge']) + ' drop']
        rows += ['add rule inet ' + TABLE + ' forward ' + rule for rule in rules]
        if active:
            # The overlay marks forwarded packets for its later MASQUERADE. Preserve
            # this peer's source identity into the private namespace, without changing
            # the overlay's shared chains or NAT of ordinary Internet traffic.
            rows += ['add rule inet ' + TABLE + ' postrouting iifname ' + q(s['host_bridge'])
                     + ' oifname ' + q(s['host_veth']) + ' ip saddr ' + s['mac_peer']
                     + ' ip daddr @corp4 meta mark set meta mark & 0xff00ffff']
        return '\n'.join(rows) + '\n'

    def apply(self, active, reserve):
        owner = self.parent.owner() or {}
        current = self.inspect(reserve)
        if current is not None and not self.owned(current):
            raise RuntimeError('foreign_tailnet_guard_requires_operator')
        if active and current is None:
            raise RuntimeError('tailnet_guard_must_be_blocked_before_activation')
        if not owner.get('resources', {}).get('host_chain'):
            self.parent.record(host_chain=True)
        self.parent.command(['nft', '-f', '-'], self.render(active, current is not None), reserve=reserve)
        value = self.inspect(reserve)
        if value is None:
            raise RuntimeError('tailnet_guard_creation_unverified')
        self.save_receipt(value)

    def remove(self, reserve):
        if self.parent.c.get('retain_blocked_guard'):
            # The boot service keeps its own receipt after mode resources are
            # withdrawn. Advertised subnets must never fall back to ordinary WAN.
            return self.apply(False, reserve)
        current = self.inspect(reserve)
        if current is None:
            return
        if not self.owned(current):
            raise RuntimeError('foreign_tailnet_guard_requires_operator')
        self.parent.command(['nft', 'delete', 'table', 'inet', TABLE], reserve=reserve)
        if self.inspect(reserve) is not None:
            raise RuntimeError('tailnet_guard_withdrawal_unverified')
        if self.parent.c.get('guard_state'):
            Path(self.parent.c['guard_state']).unlink(missing_ok=True)
