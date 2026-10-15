"""Portable, credential-free planning primitives. No network or PF changes on import.

Node validation and narrow PF rendering adapted from the existing local guard.
"""
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

VERSION = "2.0.0"
CORE_AI = {"chatgpt.com", "api.openai.com", "claude.ai", "api.anthropic.com"}
PROTECTED = sorted(CORE_AI | {"openai.com", "oaistatic.com", "claude.com", "gemini.google.com", "generativelanguage.googleapis.com", "grok.com", "x.ai", "perplexity.ai", "copilot.microsoft.com", "githubcopilot.com", "openrouter.ai", "oaiusercontent.com", "chat.com", "claudeusercontent.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "pplx.ai", "chathub.gg", "poe.com", "mistral.ai"})
APNIC = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"


def atomic(path, content, mode=0o600):
    path = Path(path)
    temp = path.with_name(path.name + '.new-' + str(os.getpid()))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(temp, flags, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content.encode() if isinstance(content, str) else content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()

def valid_node_host(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        return False
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value)
                    and '.' in value and all(1 <= len(label) <= 63 for label in value.split('.')))

def validate_node_records(records):
    fields = {'subscription', 'name', 'host', 'port', 'type'}
    if not isinstance(records, list) or not 1 <= len(records) <= 5000:
        raise RuntimeError('Empty or excessive node snapshot; existing rules retained')
    result = []
    for node in records:
        if not isinstance(node, dict) or set(node) != fields or any(not isinstance(v, str) for v in node.values()):
            raise RuntimeError('Node snapshot contains unexpected fields; no credentials accepted')
        if any(not node[k] or len(node[k]) > 512 or re.search(r'[\x00-\x1f\x7f]', node[k])
               for k in ('subscription', 'name')):
            raise RuntimeError('Unsafe node labels')
        if node['type'] not in {'Trojan', 'VLESS', 'Hysteria2', 'Shadowsocks', 'Socks5'}:
            raise RuntimeError('Unsupported node transport; existing rules retained')
        if not valid_node_host(node['host']):
            raise RuntimeError('Node host is not a public address or safe domain')
        port_range(node['port'])
        bounds = [int(v) for v in node['port'].split('-')]
        if len(bounds) == 2 and (node['type'] != 'Hysteria2' or bounds[1] - bounds[0] > 10000):
            raise RuntimeError('Unexpected transport port range; existing rules retained')
        if any(bounds[0] <= reserved <= bounds[-1] for reserved in (53, 853)):
            raise RuntimeError('Proxy discovery cannot open plain DNS/DoT ports')
        normalized=dict(node)
        try:normalized['host']=str(ipaddress.ip_address(node['host']))
        except ValueError:normalized['host']=node['host'].lower()
        result.append(normalized)
    canonical = {tuple(sorted(n.items())) for n in result}
    return sorted((dict(n) for n in canonical), key=lambda n: tuple(n[k] for k in sorted(fields)))

def node_counts(records):
    return {s: sum(n['subscription'] == s for n in records) for s in sorted({n['subscription'] for n in records})}

def node_fingerprint(records):
    return hashlib.sha256(json.dumps(validate_node_records(records), sort_keys=True, ensure_ascii=False).encode()).hexdigest()

def port_range(value):
    if not re.fullmatch(r'\d{1,5}(?:-\d{1,5})?', str(value)):
        raise RuntimeError('Invalid port/range')
    numbers = [int(x) for x in str(value).split('-')]
    if not all(1 <= x <= 65535 for x in numbers) or numbers != sorted(numbers):
        raise RuntimeError('Invalid port/range bounds')
    return ':'.join(str(n) for n in numbers)

def cn_networks(text):
    nets = {4: [], 6: []}
    for line in text.splitlines():
        fields = line.split('|')
        if len(fields) < 7 or fields[:2] != ['apnic', 'CN']:
            continue
        if fields[6] not in ('allocated', 'assigned'):
            continue
        kind, start, size = fields[2:5]
        if kind == 'ipv4':
            first = ipaddress.IPv4Address(start)
            last = ipaddress.IPv4Address(int(first) + int(size) - 1)
            nets[4].extend(ipaddress.summarize_address_range(first, last))
        elif kind == 'ipv6':
            nets[6].append(ipaddress.IPv6Network(start + '/' + size))
    return {str(k): [str(n) for n in ipaddress.collapse_addresses(v)] for k, v in nets.items()}

def noncomments(text):
    return [x.strip() for x in text.splitlines() if x.strip() and not x.lstrip().startswith('#')]

def rules(m, ifaces, policy=None):
    virtual = ['lo0'] + sorted(i for i in ifaces if re.fullmatch(r'utun\d+', i))
    lines = ['# Generated from observed node endpoints. No credentials.',
             '# Virtual traffic creates no floating states on physical interfaces.']
    for iface in virtual:
        lines.append(f'pass quick on {iface} all no state label "SRP_virtual"')
    if policy:
        protected = sorted({a for values in policy['protected_addresses'].values() for a in values})
        # No exception is placed above this rule on physical interfaces. A
        # protected address is blocked even if allocation data label it CN.
        lines.append('table <SRP_AI> persist { ' + ', '.join(protected) + ' }')
        lines.append('block drop out quick from any to <SRP_AI> label "SRP_AI_deny"')
        for family in ('4', '6'):
            lines.append('table <SRP_CN' + family + '> persist { '
                         + ', '.join(policy['cn_networks'][family]) + ' }')
    lan4 = '{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }'
    # Allow LAN DNS resolution to local gateway/router before dropping public DNS
    lines.append(f'pass out quick inet proto udp from any to {lan4} port 53 no state label "SRP_LAN_DNS"')
    lines.append('pass out quick inet6 proto udp from any to { fe80::/10, fc00::/7 } port 53 no state label "SRP_LAN_DNS6"')
    # Plain DNS/DoT to public destinations is blocked to prevent leaks.
    lines.append('block drop out quick proto { tcp, udp } from any to any port { 53, 853 } label "SRP_DNS_deny"')
    # Narrow address-assignment, IPv6 link control, and Apple Continuity
    # (AirDrop, Handoff, Sidecar, Universal Control, iPhone Mirroring, Bonjour/mDNS).
    dhcp = '{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 255.255.255.255 }'
    awdl_ifaces = sorted({i for i in ifaces if re.fullmatch(r'(?:awdl|llw)\d+', i)} | {'awdl0', 'llw0'})
    for iface in awdl_ifaces:
        lines.append(f'pass quick on {iface} inet6 from {{ ::/128, fe80::/10, fc00::/7 }} to {{ fe80::/10, fc00::/7, ff02::/16 }} no state label "SRP_continuity"')
        lines.append(f'pass quick on {iface} inet from 169.254.0.0/16 to {{ 169.254.0.0/16, 224.0.0.0/24, 255.255.255.255 }} no state label "SRP_continuity"')
    lines += [
        f'pass out quick inet proto udp from any port 68 to {dhcp} port 67 no state label "SRP_DHCP4"',
        f'pass in quick inet proto udp from {dhcp} port 67 to any port 68 no state label "SRP_DHCP4"',
        'pass out quick inet6 proto udp from { ::/128, fe80::/10 } port 546 to { fe80::/10, ff02::1:2 } port 547 no state label "SRP_DHCP6"',
        'pass in quick inet6 proto udp from fe80::/10 port 547 to { fe80::/10, ff02::1:2 } port 546 no state label "SRP_DHCP6"',
        'pass out quick inet6 proto icmp6 from { ::/128, fe80::/10 } to { fe80::/10, ff02::/16 } icmp6-type { 130, 131, 132, 133, 135, 136, 143 } no state label "SRP_ND6"',
        'pass in quick inet6 proto icmp6 from { ::/128, fe80::/10 } to any icmp6-type { 130, 131, 132, 133, 134, 135, 136, 143 } no state label "SRP_ND6"',
        f'pass out quick inet proto igmp from {lan4} to 224.0.0.0/4 allow-opts no state label "SRP_mDNS"',
        f'pass in quick inet proto igmp from {lan4} to 224.0.0.0/4 allow-opts no state label "SRP_mDNS"',
        f'pass out quick inet proto udp from {lan4} to {{ 224.0.0.0/24, 239.255.255.0/24, 255.255.255.255 }} no state label "SRP_mDNS"',
        f'pass in quick inet proto udp from {lan4} to {{ 224.0.0.0/24, 239.255.255.0/24, 255.255.255.255 }} no state label "SRP_mDNS"',
        'pass out quick inet6 proto udp from { ::/128, fe80::/10, fc00::/7 } to ff02::/16 no state label "SRP_mDNS"',
        'pass in quick inet6 proto udp from { ::/128, fe80::/10, fc00::/7 } to ff02::/16 no state label "SRP_mDNS"',
        f'pass out quick inet proto {{ tcp, udp, icmp }} from {lan4} to {lan4} keep state (if-bound) label "SRP_LAN4"',
        f'pass in quick inet proto {{ tcp, udp, icmp }} from {lan4} to {lan4} keep state (if-bound) label "SRP_LAN4"',
        'pass out quick inet6 proto { tcp, udp, icmp6 } from { fe80::/10, fc00::/7 } to { fe80::/10, fc00::/7 } keep state (if-bound) label "SRP_LAN6"',
        'pass in quick inet6 proto { tcp, udp, icmp6 } from { fe80::/10, fc00::/7 } to { fe80::/10, fc00::/7 } keep state (if-bound) label "SRP_LAN6"',
    ]
    peers = set()
    for node in m['records']:
        # Reviewed chained exits must never be physical entry exceptions.
        if node['host'] in m['excluded_hosts']:
            continue
        protocols = ['udp'] if node['type'] == 'Hysteria2' else ['tcp', 'udp'] if node['type'] == 'Shadowsocks' else ['tcp']
        for address in m['addresses'][node['host']]:
            if address in m['excluded_addresses']:
                raise RuntimeError('Upstream address overlaps final exit B')
            for proto in protocols:
                peers.add((address, proto, port_range(node['port'])))
    for address, proto, port in sorted(peers):
        family = 'inet6' if ':' in address else 'inet'
        # Interface-bound state prevents a TUN state authorizing a Wi-Fi packet.
        lines.append(f'pass out quick {family} proto {proto} from any to {address} port {port} keep state (if-bound) label "SRP_proxy"')
    if policy:
        for family in ('4', '6'):
            family_name = 'inet' if family == '4' else 'inet6'
            lines.append(f'pass out quick {family_name} proto {{ tcp, udp }} from any to <SRP_CN{family}> keep state (if-bound) label "SRP_CN_direct"')
    lines += ['block drop out quick all label "SRP_block_out"',
              'block drop in quick all label "SRP_block_in"']
    return '\n'.join(lines) + '\n'

def now():
    return datetime.datetime.now(datetime.timezone.utc)


def age(value):
    parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timestamp requires a timezone')
    return (now() - parsed).total_seconds()


def private_json(path, uid, max_age=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077 or info.st_size > 2_000_000:
            raise ValueError('Private file ownership/mode/size is invalid')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            value = json.loads(stream.read(2_000_001))
    finally:
        os.close(fd)
    if max_age is not None and not -5 <= age(value['observed_at']) <= max_age:
        raise ValueError('Snapshot is stale or future-dated; previous rules retained')
    return value


def read_snapshot(path, uid):
    value = private_json(path, uid, max_age=90)
    if value.get('version') != 1 or value.get('status') != 'ready' or value.get('unmatched_subscription_count') != 0:
        raise ValueError('Node source is incomplete; previous rules retained')
    return validate_node_records(value['records'])


def validate_policy(p):
    if p['source'] != APNIC or not re.fullmatch('[0-9a-f]{64}', p['source_sha256']):
        raise ValueError('Unrecognized allocation source')
    if age(p['prepared_at']) < -300:
        raise ValueError('Future allocation data')
    for family, minimum in ((4, 1000), (6, 100)):
        nets = p['cn_networks'][str(family)]
        if not minimum <= len(nets) <= 20000:
            raise ValueError('Unexpected CN prefix count')
        for n in nets:
            net = ipaddress.ip_network(n)
            if net.version != family or not net.is_global or net.prefixlen < (8 if family == 4 else 16):
                raise ValueError('Non-public or overbroad domestic range')
    count = sum(ipaddress.ip_network(n).num_addresses for n in p['cn_networks']['4'])
    if not 100_000_000 <= count <= 500_000_000:
        raise ValueError('Unexpected domestic address coverage')
    addresses = p['protected_addresses']
    if not CORE_AI <= set(addresses) or not set(addresses) <= set(PROTECTED):
        raise ValueError('AI deny data missing or unknown')
    for ips in addresses.values():
        if not ips or len(ips) > 1000 or any(not ipaddress.ip_address(a).is_global for a in ips):
            raise ValueError('Invalid AI addresses')
    return p


def validate_manifest(m):
    if m.get('version') != VERSION:
        raise ValueError('Unsupported installation version')
    if not isinstance(m['uid'], int) or m['uid'] <= 0 or not isinstance(m['gid'], int) or m['gid'] < 0:
        raise ValueError('A normal login user is required')
    if not re.fullmatch(r'(?:http|socks5h)://127\.0\.0\.1:[0-9]{1,5}', m['proxy']):
        raise ValueError('Proxy must be an observed loopback listener')
    port_range(m['proxy'].rsplit(':', 1)[1])
    if not re.fullmatch(r'[A-Fa-f0-9-]{36}', m['vpn_service']):
        raise ValueError('Invalid observed VPN service identifier')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,15}', m['physical_interface']):
        raise ValueError('Invalid physical interface')
    records = validate_node_records(m['records'])
    if not m['addresses'] or set(m['addresses']) != {r['host'] for r in records}:
        raise ValueError('Incomplete endpoint resolution')
    for ips in m['addresses'].values():
        if not ips or len(ips) > 1000 or any(not ipaddress.ip_address(a).is_global for a in ips):
            raise ValueError('Endpoint addresses must be public')
    excluded = set(m['excluded_hosts'])
    if not excluded <= {r['host'] for r in records}:
        raise ValueError('Excluded chain exit not present in source')
    if set(m['excluded_addresses']) != {a for h in excluded for a in m['addresses'][h]}:
        raise ValueError('Excluded exit addresses do not match source')
    approved = set(m['direct_socks5_hosts'])
    if any(r['type'] == 'Socks5' and r['host'] not in excluded | approved for r in records):
        raise ValueError('Unclassified SOCKS5 endpoint; review chain instead of guessing')
    if not ipaddress.ip_address(m['observed_exit']).is_global:
        raise ValueError('Invalid proxy exit baseline')
    policy = validate_policy(m['policy'])
    protected = {a for ips in policy['protected_addresses'].values() for a in ips}
    for row in records:
        if any(row['host'] == h or row['host'].endswith('.' + h) for h in PROTECTED):
            raise ValueError('AI hostname cannot be a proxy exception')
        if row['host'] not in excluded and set(m['addresses'][row['host']]) & (protected | set(m['excluded_addresses'])):
            raise ValueError('Proxy exception overlaps protected or chained exit address')
    # Even a CN classification must not allow a chained exit to bypass A.
    if any(ipaddress.ip_address(a) in ipaddress.ip_network(n) for a in m['excluded_addresses']
           for n in policy['cn_networks'][str(ipaddress.ip_address(a).version)]):
        raise ValueError('Domestic allocation overlaps a chained exit')
    return m


def render(m, ifaces):
    validate_manifest(m)
    policy = m['policy'] if age(m['policy']['prepared_at']) <= 30 * 86400 else None
    # AI addresses remain denied even after allocation data expires.
    text = rules(m, ifaces, m['policy'])
    if policy is None:
        text = '\n'.join(l for l in text.splitlines() if 'SRP_CN_direct' not in l) + '\n'
    return text


def listener_candidates(text):
    """Parse lsof -Fpcun output, accepting only loopback packet-tunnel ports."""
    pid = uid = None
    process = ''
    rows = set()
    for line in text.splitlines():
        if line.startswith('p'):
            pid, uid, process = int(line[1:]), None, ''
        elif line.startswith('u'):
            uid = int(line[1:])
        elif line.startswith('c'):
            process = line[1:]
        elif line.startswith('n') and pid and uid is not None and process.startswith('MacPacket'):
            match = re.fullmatch(r'(?:127\.0\.0\.1|\[::1\]):([0-9]+)', line[1:])
            if match and 1 <= int(match[1]) <= 65535:
                rows.add((pid, uid, int(match[1])))
    return sorted(rows)


def profile_sections(text):
    matches = list(re.finditer(r'(?m)^\[([^\]\r\n]+)\][ \t]*\r?$', text))
    names = [m[1].strip() for m in matches]
    if len(names) != len(set(names)) or 'General' not in names or 'Rule' not in names:
        raise ValueError('Profile requires single General/Rule sections')
    return {m[1].strip(): (m.end(), matches[i+1].start() if i+1 < len(matches) else len(text))
            for i, m in enumerate(matches)}


def merge_profile(original, fragment):
    sections = profile_sections(original)
    fsecs = profile_sections(fragment)
    general = fragment[slice(*fsecs['General'])]
    updates = dict(re.findall(r'(?m)^([a-z][a-z0-9-]*)\s*=\s*(.+)$', general))
    a, b = sections['General']
    old_general = original[a:b]
    lines = []
    for line in old_general.splitlines():
        match = re.match(r'^\s*([a-z][a-z0-9-]*)\s*=', line)
        if match and match[1] in updates:
            continue
        lines.append(line)
    new_general = '\n' + '\n'.join(k+' = '+v for k,v in updates.items()) + '\n' + '\n'.join(lines) + '\n\n'
    a, b = sections['Rule']
    old_rules = original[a:b]
    new_rules = fragment[slice(*fsecs['Rule'])]
    additions = [l.strip() for l in new_rules.splitlines() if l.strip() and not l.lstrip().startswith('#')]
    tail = ['DOMAIN-SUFFIX,cn,DIRECT', 'GEOIP,CN,DIRECT', 'FINAL,PROXY']
    head = [l for l in additions if l not in tail]
    preserved = []
    for line in old_rules.splitlines():
        clean = line.strip()
        if clean in additions or re.match(r'^(FINAL|MATCH),', clean) or re.match(r'^GEOIP,CN,', clean):
            continue
        preserved.append(line)
    merged_rules = '\n' + '\n'.join(head + preserved + tail) + '\n\n'
    result = original
    for (a,b),value in sorted([(sections['General'],new_general),(sections['Rule'],merged_rules)],reverse=True):
        result = result[:a] + value + result[b:]
    return result


def dns_query(host, kind, identifier):
    import struct
    if not valid_node_host(host) or ':' in host:
        raise ValueError('Invalid DNS hostname')
    labels=host.rstrip('.').split('.')
    question=b''.join(bytes([len(label)])+label.encode('ascii') for label in labels)+b'\x00'
    return struct.pack('!HHHHHH',identifier,0x0100,1,0,0,0)+question+struct.pack('!HH',kind,1)


def dns_answers(data, identifier):
    """Bounded DNS wire parser for IN A/AAAA; no archived objects or code execution."""
    import struct
    if len(data)<12 or len(data)>65535:
        raise ValueError('Invalid DNS response size')
    ident,flags,questions,answers,_,_=struct.unpack('!HHHHHH',data[:12])
    if ident!=identifier or not flags&0x8000 or flags&0x0200 or flags&0x000f or questions!=1 or answers>1000:
        raise ValueError('Invalid/truncated/error DNS response')
    def skip_name(offset):
        for _ in range(128):
            if offset>=len(data):raise ValueError('Truncated DNS name')
            length=data[offset]
            if length&0xc0==0xc0:
                if offset+1>=len(data) or ((length&0x3f)<<8|data[offset+1])>=len(data):
                    raise ValueError('Invalid DNS pointer')
                return offset+2
            if length&0xc0 or length>63:raise ValueError('Invalid DNS label')
            offset+=1
            if not length:return offset
            offset+=length
        raise ValueError('Excessive DNS name')
    offset=skip_name(12)+4
    if offset>len(data):raise ValueError('Truncated DNS question')
    ips=[]
    for _ in range(answers):
        offset=skip_name(offset)
        if offset+10>len(data):raise ValueError('Truncated DNS answer')
        kind,klass,_,size=struct.unpack('!HHIH',data[offset:offset+10]);offset+=10
        if offset+size>len(data):raise ValueError('Truncated DNS rdata')
        if klass==1 and (kind,size) in ((1,4),(28,16)):
            ip=ipaddress.ip_address(data[offset:offset+size])
            if not ip.is_global:raise ValueError('Non-public node DNS answer')
            ips.append(str(ip))
        offset+=size
    return ips
