#!/usr/bin/env python3
"""Portable Shadowrocket guard. Planning is unprivileged; PF mutations are explicit.

Never reads vendor data as root. Never modifies a subscription, node or profile.
The sandboxed helper exports credential-free metadata after user authorization.
"""
import argparse
import concurrent.futures
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import core

INSTALL = Path('/Library/Application Support/ShadowrocketRoutingGuard')
LABEL = 'org.shadowrocket-routing.guard'
PLIST = Path('/Library/LaunchDaemons') / (LABEL + '.plist')
ANCHOR = 'com.apple/000.shadowrocket-portable'
PF = '/sbin/pfctl'
PFCONF = Path('/etc/pf.conf')
APP_ID = 'org.shadowrocket-routing.NodeSync'
AGENT_LABEL = 'org.shadowrocket-routing.node-sync'
APP_NAME = 'Shadowrocket Routing Node Sync.app'
BEGIN, END = '# BEGIN ShadowrocketRoutingGuard\n', '# END ShadowrocketRoutingGuard\n'
LOAD_BLOCK = BEGIN + 'load anchor "' + ANCHOR + '" from "' + str(INSTALL / 'guard.pf') + '"\n' + END
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'en_US.UTF-8'}
STOCK = ['scrub-anchor "com.apple/*"', 'nat-anchor "com.apple/*"',
         'rdr-anchor "com.apple/*"', 'dummynet-anchor "com.apple/*"',
         'anchor "com.apple/*"', 'load anchor "com.apple" from "/etc/pf.anchors/com.apple"']


def run(args, timeout=20, check=True, text=None, user=None):
    identity = dict(user=user['uid'], group=user['gid'], extra_groups=[]) if user and os.geteuid() == 0 else {}
    p = subprocess.run(args, input=text, capture_output=True, text=True, timeout=timeout,
                       env=ENV, **identity)
    if check and p.returncode:
        # Do not include arguments, URLs, arbitrary remote error text or metadata.
        raise RuntimeError(Path(args[0]).name + ' failed (exit ' + str(p.returncode) + ')')
    return p


def require_mac():
    if sys.platform != 'darwin':
        raise RuntimeError('macOS only')


def require_root():
    require_mac()
    if os.geteuid() != 0:
        raise RuntimeError('Run this specific action using sudo in your own terminal; never share the password')


def login_user():
    uid = int(os.environ.get('SUDO_UID', os.getuid()))
    if uid <= 0:
        raise ValueError('Run from the normal login user, not a root login shell')
    entry = pwd.getpwuid(uid)
    return dict(uid=uid, gid=entry.pw_gid, home=entry.pw_dir)


def snapshot_path(home):
    return Path(home) / 'Library/Containers' / APP_ID / 'Data/Library/Application Support/ShadowrocketRoutingSync/snapshot.json'


def ifaces():
    return run(['/sbin/ifconfig', '-l']).stdout.split()


def physical_interface():
    table = run(['/usr/sbin/netstat', '-rn', '-f', 'inet']).stdout
    rows = [line.split() for line in table.splitlines()]
    candidates = sorted({parts[3] for parts in rows if len(parts) >= 4 and parts[0] == 'default'
                         and re.fullmatch(r'en[0-9]+', parts[3])})
    if len(candidates) != 1:
        raise ValueError('Physical default interface is ambiguous; no rules changed')
    return candidates[0]


def vpn_service():
    raw = run(['/usr/sbin/scutil', '--nc', 'list']).stdout
    connected = re.findall(r'\(Connected\)\s+([A-Fa-f0-9-]{36})', raw)
    if len(connected)>1:
        raise ValueError('Another VPN is connected; reviewed coexistence is required before installing a system guard')
    services = re.findall(r'\((Connected|Disconnected|Connecting)\)\s+([A-Fa-f0-9-]{36})[^\n]*\(com\.liguangming\.Shadowrocket\)', raw)
    if len(services) != 1 or services[0][0] != 'Connected':
        raise ValueError('Connect the existing Shadowrocket route before planning')
    return services[0][1]


def provider_rows(uid):
    raw = run(['/usr/sbin/lsof', '-nP', '-iTCP', '-sTCP:LISTEN', '-Fpcun'], check=False).stdout
    rows = [r for r in core.listener_candidates(raw) if r[1] == uid]
    valid = []
    for pid, owner, port in rows:
        command = run(['/bin/ps', '-ww', '-p', str(pid), '-o', 'comm=']).stdout.strip()
        if 'Shadowrocket.app/' in command and command.endswith('/MacPacketTunnel'):
            valid.append((pid, owner, port))
    return valid


def curl(proxy, url, extra=(), maximum=20):
    if not re.fullmatch(r'(http|socks5h)://127\.0\.0\.1:[0-9]{1,5}', proxy):
        raise ValueError('Invalid local proxy')
    return run(['/usr/bin/curl', '--fail', '-sS', '--http1.1', '--proxy', proxy,
                '--connect-timeout', '5', '--max-time', str(maximum), '--max-filesize', '10000000',
                *extra, url], timeout=maximum+3).stdout


def exit_ip(proxy):
    value = curl(proxy, 'https://api.ipify.org', maximum=12).strip()
    if not ipaddress.ip_address(value).is_global:
        raise ValueError('Exit baseline is not a public IP')
    return value


def discover_proxy(uid):
    rows = provider_rows(uid)
    candidates = []
    for port in sorted({r[2] for r in rows}):
        # Both protocols can work on a mixed listener; use first working scheme.
        for scheme in ('http', 'socks5h'):
            value = scheme + '://127.0.0.1:' + str(port)
            try:
                observed = exit_ip(value)
                candidates.append((value, observed))
                break
            except (RuntimeError, ValueError, subprocess.TimeoutExpired):
                continue
    if len(candidates) != 1:
        raise ValueError('No unique working Shadowrocket loopback listener; no guessed port')
    return candidates[0]


def resolve(host, proxy):
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global:
            raise ValueError('Non-public endpoint')
        return [str(address)]
    except ValueError:
        if not core.valid_node_host(host):
            raise ValueError('Unsafe endpoint hostname')
    values = []
    for kind in ('A', 'AAAA'):
        url = 'https://cloudflare-dns.com/dns-query?' + urllib.parse.urlencode({'name':host,'type':kind})
        data = json.loads(curl(proxy, url, ['-H','accept: application/dns-json']))
        if data.get('Status') != 0:
            raise ValueError('Endpoint DNS lookup failed; previous rules retained')
        for row in data.get('Answer', []):
            if row.get('type') in (1, 28):
                address = ipaddress.ip_address(row['data'])
                if not address.is_global:
                    raise ValueError('Non-public DNS response')
                values.append(str(address))
    if not values:
        raise ValueError('No public endpoint DNS response')
    return sorted(set(values))


def resolve_node(host, proxy):
    # Encrypted node bootstrap is independent of a failed/unlisted proxy.
    # This narrowly scoped resolver is NEVER used for AI destination queries.
    try:
        address=ipaddress.ip_address(host)
        if not address.is_global:raise ValueError('Non-public node address')
        return [str(address)]
    except ValueError:
        if not core.valid_node_host(host):raise ValueError('Unsafe node hostname')
    host=host.lower()
    if any(host==h or host.endswith('.'+h) for h in core.PROTECTED):
        raise ValueError('AI hostname cannot use node bootstrap DNS')
    values=[]
    for kind in (1,28):
        identifier=int.from_bytes(os.urandom(2),'big')
        wire=core.dns_query(host,kind,identifier)
        response=subprocess.run(['/usr/bin/curl','--noproxy','*','--fail','-sS','--http1.1',
            '--connect-timeout','3','--max-time','8','--max-filesize','65535',
            '-H','content-type: application/dns-message','-H','accept: application/dns-message',
            '--data-binary','@-','https://223.5.5.5/dns-query'],input=wire,
            capture_output=True,timeout=10,env=ENV)
        if response.returncode:raise ValueError('Encrypted node bootstrap DNS unavailable; old rules retained')
        values.extend(core.dns_answers(response.stdout,identifier))
    if not values:raise ValueError('Node bootstrap returned no public address')
    return sorted(set(values))


def new_policy(proxy, previous=None):
    raw = curl(proxy, core.APNIC, maximum=30)
    networks = core.cn_networks(raw)
    addresses = copy.deepcopy(previous['protected_addresses']) if previous else {}
    for host in core.PROTECTED:
        try:
            addresses[host] = sorted(set(resolve(host, proxy)) | set(addresses.get(host, [])))
        except Exception:
            if host in core.CORE_AI and not addresses.get(host):
                raise
    p = dict(source=core.APNIC, source_sha256=hashlib.sha256(raw.encode()).hexdigest(),
             prepared_at=core.now().isoformat(), cn_networks=networks, protected_addresses=addresses)
    return core.validate_policy(p)


def resolve_records(records, proxy, old=None):
    hosts = sorted({r['host'] for r in records})
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(lambda h: old[h] if old and h in old else resolve_node(h, proxy), hosts))
    return dict(zip(hosts, values))


def syntax(path):
    run([PF, '-n', '-f', str(path)])


def preflight():
    """No mutations. Refuse legacy installs and custom PF hook ordering."""
    if Path('/Library/LaunchDaemons/local.shadowrocket.egress-guard.plist').exists():
        raise ValueError('Existing legacy guard detected; do not install a second guard or uninstall automatically')
    if PFCONF.is_symlink():
        raise ValueError('Symlinked PF configuration is not supported')
    disk = core.noncomments(PFCONF.read_text().replace(LOAD_BLOCK, ''))
    if disk != STOCK:
        raise ValueError('Custom PF configuration requires reviewed integration; no root rules overwritten')
    filters = core.noncomments(run([PF, '-sr']).stdout)
    expected = [['anchor "com.apple/*" all'], ['scrub-anchor "com.apple/*" all fragment reassemble','anchor "com.apple/*" all']]
    if filters and filters not in expected:
        raise ValueError('Non-stock PF root filters; no root rules overwritten')
    children = run([PF, '-a', 'com.apple', '-s', 'Anchors']).stdout.split()
    if any(c.split('/')[-1] < ANCHOR.split('/')[-1] for c in children):
        raise ValueError('An earlier child anchor could bypass the guard')
    info = run([PF, '-v', '-s', 'Interfaces']).stdout
    for block in re.split(r'(?m)^(?=\S)', info):
        iface = block.split()[0].rstrip(':') if block.split() else ''
        if 'skip' in block.lower() and iface and iface != 'lo0' and not re.fullmatch(r'utun[0-9]+', iface):
            raise ValueError('PF skip flag on non-virtual interface')
    return not filters


def reference():
    token_file = INSTALL / 'enable-token'
    old = token_file.read_text().strip() if token_file.exists() else None
    references = run([PF, '-s', 'References']).stdout
    if not old or not re.search(r'\b'+re.escape(old)+r'\b', references):
        value = run([PF, '-E'])
        found = re.search(r'Token\s*:\s*([0-9]+)', value.stdout+value.stderr, re.I)
        if not found:
            raise ValueError('Owned PF enable reference not returned')
        core.atomic(token_file, found[1]+'\n')


def clear_local_states():
    """One-time/update cutover: existing non-loopback states must not bypass PF."""
    text = run(['/sbin/ifconfig']).stdout
    for value in set(re.findall(r'\binet6?\s+([^\s%]+)', text)):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if not address.is_loopback and not address.is_unspecified:
            run([PF, '-k', str(address)])
            run([PF, '-k', '::/0' if address.version == 6 else '0.0.0.0/0', '-k', str(address)])


def apply(m, purge=False):
    empty = preflight()
    candidate = INSTALL / 'candidate.pf'
    content = core.render(m, ifaces())
    core.atomic(candidate, content)
    syntax(candidate)
    if empty:
        run([PF, '-f', str(PFCONF)])  # only exact stock config + own load directive
    reference()
    run([PF, '-a', ANCHOR, '-f', str(candidate)])
    # Fail closed if persistence or state cleanup fails after activation.
    core.atomic(INSTALL/'guard.pf', content, 0o600)
    if purge:
        clear_local_states()
    active = run([PF, '-a', ANCHOR, '-sr']).stdout
    if not all(label in active for label in ('SRP_AI_deny','SRP_block_out','SRP_block_in')):
        raise ValueError('Kernel guard readback incomplete')
    return hashlib.sha256(content.encode()).hexdigest()


def machine_match(m):
    core.validate_manifest(m)
    entry = pwd.getpwuid(m['uid'])
    if entry.pw_dir != m['home'] or entry.pw_gid != m['gid']:
        raise ValueError('Plan belongs to another local user/machine')
    if m['snapshot'] != str(snapshot_path(m['home'])):
        raise ValueError('Unexpected snapshot path')
    if vpn_service() != m['vpn_service'] or physical_interface() != m['physical_interface']:
        raise ValueError('VPN or physical default interface changed; prepare a new plan')
    if not any(port == int(m['proxy'].rsplit(':',1)[1]) for _,_,port in provider_rows(m['uid'])):
        raise ValueError('Observed Shadowrocket listener changed')
    if exit_ip(m['proxy']) != m['observed_exit']:
        raise ValueError('Current exit changed since review; prepare a new plan')


def plan(args):
    require_mac()
    if os.geteuid() == 0:
        raise ValueError('Create plans as the normal user; do not use sudo')
    user = login_user()
    records = core.read_snapshot(snapshot_path(user['home']), user['uid'])
    proxy, observed_exit = discover_proxy(user['uid'])
    excluded = sorted({h.lower() for h in (args.chain_exit or [])})
    approved = sorted({h.lower() for h in (args.direct_socks5 or [])})
    # Do not infer chain linkage from protocol or a display name.
    unresolved = {r['host'] for r in records if r['type']=='Socks5'} - set(excluded) - set(approved)
    if unresolved:
        raise ValueError('SOCKS5 chain relationship needs review: classify with --chain-exit HOST or --direct-socks5 HOST; no rules changed')
    if not set(excluded) <= {r['host'] for r in records}:
        raise ValueError('Specified chain exit is not present in the current inventory')
    addresses = resolve_records(records, proxy)
    m = dict(version=core.VERSION, **user, proxy=proxy, observed_exit=observed_exit,
             vpn_service=vpn_service(), physical_interface=physical_interface(),
             observed_at=core.now().isoformat(), records=records, addresses=addresses,
             excluded_hosts=excluded, excluded_addresses=sorted({a for h in excluded for a in addresses.get(h,[])}),
             direct_socks5_hosts=approved, snapshot=str(snapshot_path(user['home'])),
             policy=new_policy(proxy), node_fingerprint=core.node_fingerprint(records))
    core.validate_manifest(m)
    output = Path(args.output).expanduser()
    if output.exists() or output.is_symlink():
        raise ValueError('Plan output already exists; keep previous review or choose another path')
    output.mkdir(mode=0o700, parents=True)
    core.atomic(output/'plan.json', json.dumps(m,ensure_ascii=False,indent=2))
    core.atomic(output/'candidate.pf',core.render(m,ifaces()))
    syntax(output/'candidate.pf')
    print(json.dumps(dict(plan=str(output/'plan.json'),nodes=len(records),proxy=proxy,
          excluded_chain_exits=len(excluded),candidate_syntax='passed',active_firewall_changed=False),ensure_ascii=False))


def root_tree(path):
    for ancestor in [path]+list(path.parents):
        if ancestor == Path('/'):
            break
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Privileged runtime path is not root-controlled')


def install(args):
    require_root()
    if not args.profile_applied:
        raise ValueError('First merge/compile/activate the profile in Shadowrocket; then pass --profile-applied')
    if INSTALL.exists() or INSTALL.is_symlink() or PLIST.exists() or PLIST.is_symlink():
        raise ValueError('Portable guard already present; use status, sync or explicit uninstall')
    uid = login_user()['uid']
    m = core.private_json(Path(args.plan),uid)
    if m.get('uid') != uid:
        raise ValueError('Plan owner differs from the sudo login user')
    if not -5 <= core.age(m['observed_at']) <= 1800:
        raise ValueError('Review plan is older than 30 minutes')
    machine_match(m)
    if core.node_fingerprint(core.read_snapshot(Path(m['snapshot']),uid)) != m['node_fingerprint']:
        raise ValueError('Node inventory changed since review')
    preflight()
    runtime = Path(sys.executable).resolve()
    root_tree(runtime)
    source = Path(__file__).resolve().parent
    old = PFCONF.read_text()
    root_tree(INSTALL.parent)
    root_tree(PLIST.parent)
    INSTALL.mkdir(mode=0o700)
    for name in ('core.py','portable_guard.py'):
        core.atomic(INSTALL/name,(source/name).read_bytes(),0o600)
    core.atomic(INSTALL/'runtime.json',json.dumps(m,ensure_ascii=False,indent=2))
    core.atomic(INSTALL/'pf.conf.before',old)
    core.atomic(INSTALL/'guard.pf',core.render(m,ifaces()))
    syntax(INSTALL/'guard.pf')
    candidate = INSTALL/'pf.conf.candidate'
    core.atomic(candidate,old.rstrip()+'\n\n'+LOAD_BLOCK)
    syntax(candidate)
    core.atomic(PFCONF,candidate.read_bytes(),0o644)
    # From this point, failure never silently removes the blocking anchor.
    digest = apply(m,purge=True)
    daemon = dict(Label=LABEL,ProgramArguments=[str(runtime),'-I',str(INSTALL/'portable_guard.py'),'daemon'],
                  RunAtLoad=True,KeepAlive=True,ThrottleInterval=5,
                  StandardOutPath=str(INSTALL/'daemon.log'),StandardErrorPath=str(INSTALL/'daemon-errors.log'))
    core.atomic(PLIST,plistlib.dumps(daemon),0o644)
    run(['/bin/launchctl','bootstrap','system',str(PLIST)])
    status_write(dict(installed=True,verified=False,rules_sha256=digest,nodes=len(m['records']),sync_active=True))
    print('Installed with kernel readback. Firewall remains enabled. Fault test still required on this Mac.')
    print('Undo only this install: sudo '+str(runtime)+' -I "'+str(INSTALL/'portable_guard.py')+'" uninstall --remove-protection')


def status_write(value):
    value['time'] = core.now().isoformat()
    core.atomic(INSTALL/'status.json',json.dumps(value,ensure_ascii=False,indent=2))


def sync_status_write(value):
    value['time']=core.now().isoformat()
    core.atomic(INSTALL/'sync-status.json',json.dumps(value,ensure_ascii=False,indent=2))


def installed_manifest():
    require_root()
    root_tree(INSTALL)
    return core.validate_manifest(core.private_json(INSTALL/'runtime.json',0))


def candidate_sync(m, records, resolver=resolve_node):
    candidate=copy.deepcopy(m)
    candidate['records']=core.validate_node_records(records)
    # An excluded chain endpoint must retain exact protocol/port definition.
    for host in m['excluded_hosts']:
        before=sorted((r['type'],r['port']) for r in m['records'] if r['host']==host)
        after=sorted((r['type'],r['port']) for r in records if r['host']==host)
        if before!=after:
            raise ValueError('Chained exit changed or disappeared; previous rules retained')
    hosts=sorted({r['host'] for r in records})
    candidate['addresses']={h:list(m['addresses'][h]) if h in m['addresses'] else resolver(h,m['proxy']) for h in hosts}
    candidate['node_fingerprint']=core.node_fingerprint(records)
    return core.validate_manifest(candidate)


def synchronize(m):
    rows=core.read_snapshot(Path(m['snapshot']),m['uid'])
    if core.node_fingerprint(rows)==m['node_fingerprint']:
        previous=INSTALL/'sync-status.json'
        if not previous.exists() or core.private_json(previous,0).get('sync_active') is False:
            sync_status_write(dict(sync_active=True,nodes=len(rows),source_read_only=True))
        return m
    candidate=candidate_sync(m,rows)
    apply(candidate,purge=True)
    core.atomic(INSTALL/'runtime.json',json.dumps(candidate,ensure_ascii=False,indent=2))
    status_write(dict(installed=True,verified=False,note='Inventory changed; previous verification is historical'))
    sync_status_write(dict(sync_active=True,nodes=len(rows),source_read_only=True))
    return candidate


def daemon():
    m=installed_manifest()
    refresh_at=0.0
    last=None
    while True:
        try:
            current=(tuple(ifaces()),core.age(m['policy']['prepared_at'])>30*86400)
            active=run([PF,'-a',ANCHOR,'-sr']).stdout
            if current!=last or 'SRP_block_out' not in active:
                apply(m,purge=last is None or current[1])
                last=current
            reference()
            try:
                m=synchronize(m)
            except Exception:
                sync_status_write(dict(sync_active=False,previous_rules_not_flushed=True,nodes=len(m['records']),reason='Snapshot unavailable, stale, incomplete or candidate rejected'))
            if time.monotonic()-refresh_at>600:
                refresh_at=time.monotonic()
                try:
                    candidate=copy.deepcopy(m)
                    candidate['addresses']=resolve_records(m['records'],m['proxy'])
                    candidate['excluded_addresses']=sorted({a for h in m['excluded_hosts'] for a in candidate['addresses'][h]})
                    if core.age(m['policy']['prepared_at'])>86400:
                        candidate['policy']=new_policy(m['proxy'],m['policy'])
                    else:
                        for h in core.PROTECTED:
                            try:
                                candidate['policy']['protected_addresses'][h]=sorted(set(resolve(h,m['proxy']))|set(candidate['policy']['protected_addresses'].get(h,[])))
                            except Exception:
                                pass
                    core.validate_manifest(candidate)
                    if candidate!=m:
                        apply(candidate,purge=True)
                        core.atomic(INSTALL/'runtime.json',json.dumps(candidate,ensure_ascii=False,indent=2))
                        m=candidate
                except Exception:
                    pass  # DNS failure never clears the last valid anchor.
        except Exception:
            sync_status_write(dict(sync_active=False,previous_rules_not_flushed=True,reason='Maintenance failed; inspect kernel PF state'))
        time.sleep(5)


def setup_helper(args):
    require_mac()
    if os.geteuid()==0:
        raise ValueError('Run setup-helper as the normal user')
    user=login_user()
    source=Path(args.app).expanduser().resolve()
    info=plistlib.loads((source/'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier')!=APP_ID:
        raise ValueError('Unexpected helper bundle')
    run(['/usr/bin/codesign','--verify','--strict',str(source)])
    target=Path(user['home'])/'Applications'/APP_NAME
    target.parent.mkdir(exist_ok=True)
    if target.exists():
        raise ValueError('Helper already exists; do not overwrite a running bundle')
    agent=Path(user['home'])/'Library/LaunchAgents'/(AGENT_LABEL+'.plist')
    agent.parent.mkdir(exist_ok=True)
    if agent.exists():
        raise ValueError('Node agent already exists; inspect before replacement')
    shutil.copytree(source,target,symlinks=False)
    core.atomic(agent,plistlib.dumps(dict(Label=AGENT_LABEL,ProgramArguments=[str(target/'Contents/MacOS/NodeSync'),'--background'],
                RunAtLoad=True,KeepAlive=True,ThrottleInterval=10)),0o600)
    run(['/bin/launchctl','bootstrap','gui/'+str(user['uid']),str(agent)])
    run(['/usr/bin/open','-a',str(target)])
    print('In the helper, authorize only the displayed Shadowrocket group directory. Snapshot is sandbox-private.')


def uninstall(args):
    require_root()
    if not args.remove_protection:
        raise ValueError('Explicit --remove-protection is required; uninstall removes direct-connection protection')
    installed_manifest()
    old=PFCONF.read_text()
    if old.count(LOAD_BLOCK)!=1:
        raise ValueError('Managed persistence marker changed; manual reviewed removal required')
    # Only this anchor and owned enable reference, never pfctl -d or a root flush.
    run(['/bin/launchctl','bootout','system/'+LABEL],check=False)
    run([PF,'-a',ANCHOR,'-F','rules'])
    core.atomic(PFCONF,old.replace(LOAD_BLOCK,''),0o644)
    token=INSTALL/'enable-token'
    if token.exists():
        value=token.read_text().strip()
        if not value.isdigit():
            raise ValueError('Invalid owned PF reference')
        run([PF,'-X',value])
    PLIST.unlink()
    status_write(dict(installed=False,protection_removed=True))
    print('Only portable guard removed. Review backup before any manual profile rollback. Helper retained for inspection.')


def merge(args):
    if os.geteuid()==0:
        raise ValueError('Merge exported profiles as the normal user')
    src=Path(args.input).expanduser()
    dst=Path(args.output).expanduser()
    if src.resolve()==dst.resolve() or dst.exists() or dst.is_symlink():
        raise ValueError('Use a new private output file; never modify the source')
    original=src.read_text()
    fragment=Path(__file__).resolve().parent.parent/'assets/routing-fragment.conf'
    core.atomic(dst,core.merge_profile(original,fragment.read_text()))
    print('Staged merged profile (0600). Apply via Shadowrocket after making an in-app backup, compile and check active configuration.')


def status():
    require_root()
    m=installed_manifest()
    active=run([PF,'-a',ANCHOR,'-sr']).stdout
    try:
        core.read_snapshot(Path(m['snapshot']),m['uid'])
        fresh=True
    except Exception:
        fresh=False
    print(json.dumps(dict(installed=True,nodes=len(m['records']),proxy=m['proxy'],
          kernel_guard_present=all(x in active for x in ('SRP_block_out','SRP_AI_deny','SRP_block_in')),
          snapshot_fresh=fresh,note='Presence is not fault verification'),indent=2))


def connection_state(m):
    p=run(['/usr/sbin/scutil','--nc','status',m['vpn_service']],check=False,user=m)
    return p.stdout.splitlines()[0] if p.stdout.splitlines() else 'Unknown'


def sample_direct(m,host,address,timeout=3):
    p=run(['/usr/bin/curl','--noproxy','*','--http1.1','--interface',m['physical_interface'],
           '--resolve',host+':443:'+address,'--connect-timeout','2','--max-time',str(timeout),
           '-sS','-o','/dev/null','-w','%{http_code} %{local_ip} %{remote_ip}',
           'https://'+host+'/'],check=False,timeout=timeout+3)
    fields=p.stdout.split()
    return dict(exit=p.returncode,http=fields[0] if fields else '000',
                local=fields[1] if len(fields)>1 else '',remote=fields[2] if len(fields)>2 else '')


def label_count():
    raw=run([PF,'-a',ANCHOR,'-s','labels']).stdout
    return sum(int(row[2]) for l in raw.splitlines() if len(row:=l.split())>2
               and row[0] in ('SRP_AI_deny','SRP_block_out') and row[2].isdigit())


def outgoing_to(line,address,port=None):
    match=re.search(r' > '+re.escape(address)+r'\.([0-9]+):',line)
    return bool(match and (port is None or int(match[1])==port))


def verify(args):
    m=installed_manifest()
    if args.fault_test:
        status_write(dict(installed=True,verified=False,stage='verification_started'))
    if not args.fault_test:
        status()
        print('No fault injected. Use verify --fault-test only when a brief disconnect is acceptable.')
        return
    if connection_state(m)!='Connected' or exit_ip(m['proxy'])!=m['observed_exit']:
        raise ValueError('Baseline changed; no fault injected')
    targets={h:next(a for a in resolve(h,m['proxy']) if ':' not in a)
             for h in ('chatgpt.com','claude.ai','api.ipify.org')}
    nets=[ipaddress.ip_network(n) for n in m['policy']['cn_networks']['4']]
    domestic=next(a for a in resolve('www.12306.cn',m['proxy'])
                  if ':' not in a and any(ipaddress.ip_address(a) in n for n in nets))
    info=run(['/sbin/ifconfig',m['physical_interface']]).stdout
    physical_sources=re.findall(r'\binet\s+([0-9.]+)',info)
    if not physical_sources:
        raise ValueError('No physical IPv4 uplink; no fault injected')
    before=label_count()
    capture=subprocess.Popen(['/usr/sbin/tcpdump','-i',m['physical_interface'],'-Q','out','-nn','-l','-s','80','tcp or udp'],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=ENV)
    lines,errors=[],[]
    overflow=[False]
    def collect(stream,dest,maximum):
        for line in stream:
            if len(dest)<maximum:dest.append(line.strip())
            else:overflow[0]=True
    threads=[threading.Thread(target=collect,args=(capture.stdout,lines,50000),daemon=True),
             threading.Thread(target=collect,args=(capture.stderr,errors,200),daemon=True)]
    for t in threads:t.start()
    watchdog=None
    restored=False
    attempts=[]
    domestic_results=[]
    disconnected=False
    history={'last':before,'increases':0,'errors':0}
    stop_counter=threading.Event()
    def watch_counter():
        while not stop_counter.wait(.1):
            try:
                value=label_count()
                history['increases'] += value-history['last'] if value>=history['last'] else value
                history['last']=value
            except Exception:
                history['errors']+=1
    counter_thread=threading.Thread(target=watch_counter,daemon=True)
    counter_thread.start()
    try:
        deadline=time.monotonic()+4
        while not any('listening on' in l for l in errors) and time.monotonic()<deadline and capture.poll() is None:
            time.sleep(.05)
        if not any('listening on' in l for l in errors):
            raise ValueError('Packet capture unavailable; no fault injected')
        if exit_ip(m['proxy'])!=m['observed_exit']:
            raise ValueError('Capture positive control failed; no fault injected')
        # A separate process restores the service even if this verifier is killed.
        watchdog=subprocess.Popen([sys.executable,'-I',str(INSTALL/'portable_guard.py'),'restore-after','--seconds','25'],
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,env=ENV)
        run(['/usr/sbin/scutil','--nc','stop',m['vpn_service']],user=m)
        for stage in ('disconnect','reconnect'):
            if stage=='reconnect':
                run(['/usr/sbin/scutil','--nc','start',m['vpn_service']],user=m,check=False)
            disconnected=disconnected or connection_state(m)!='Connected'
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                jobs=[pool.submit(sample_direct,m,h,a,2) for h,a in targets.items()]
                dom=pool.submit(sample_direct,m,'www.12306.cn',domestic,4)
                attempts.extend(j.result() for j in jobs)
                domestic_results.append(dom.result())
    finally:
        try:
            if watchdog:
                run(['/usr/sbin/scutil','--nc','start',m['vpn_service']],user=m,check=False)
                deadline=time.monotonic()+20
                while connection_state(m)!='Connected' and time.monotonic()<deadline:time.sleep(.2)
                try:restored=connection_state(m)=='Connected' and exit_ip(m['proxy'])==m['observed_exit']
                except Exception:restored=False
                if restored:
                    watchdog.terminate()
                    watchdog.wait(timeout=3)
        except Exception:
            restored=False  # Independent watchdog remains available.
        finally:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
            try:capture.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture.kill();capture.wait(timeout=3);overflow[0]=True
            for t in threads:t.join(timeout=2)
            stop_counter.set()
            counter_thread.join(timeout=2)

    counter_complete=not counter_thread.is_alive()
    active=run([PF,'-a',ANCHOR,'-sr']).stdout
    kernel_present=all(x in active for x in ('SRP_AI_deny','SRP_block_out','SRP_block_in'))
    after=label_count()
    history['increases'] += after-history['last'] if after>=history['last'] else after
    leak_packets=sum(outgoing_to(line,a) for line in lines for a in targets.values())
    peer_packets=sum(any(outgoing_to(line,a) for a in ips) for line in lines
                     for h,ips in m['addresses'].items() if h not in m['excluded_hosts'])
    domestic_packets=sum(outgoing_to(line,domestic,443) for line in lines)
    domestic_ok=any(r['exit']==0 and r['http'].startswith(('2','3')) and r['local'] in physical_sources
                    and r['remote']==domestic for r in domestic_results) and domestic_packets>0
    stats='\n'.join(errors)
    capture_ok=bool(re.search(r'\b0 packets dropped by kernel\b',stats)) and not overflow[0]
    result=dict(installed=True,verified=bool(disconnected and restored and attempts and
                all(r['http']=='000' or r['local'] not in physical_sources for r in attempts) and leak_packets==0 and peer_packets>0
                and history['increases']>0 and not history['errors'] and domestic_ok and capture_ok and counter_complete and kernel_present),
                tested_scope='IPv4 selected AI/canary HTTPS destinations during VPN disconnect/reconnect only',
                physical_AI_canary_packets=leak_packets,proxy_transport_positive_packets=peer_packets,
                domestic_physical_positive=domestic_ok,disconnect_observed=disconnected,exit_restored=restored,
                blocking_counter_increased=history['increases']>0 and not history['errors'],capture_complete=capture_ok,counter_monitor_complete=counter_complete,kernel_guard_present=kernel_present,
                ipv6='Rules configured; no physical IPv6 fault test in this verifier',
                provider_crash='Not injected',ports_and_subscriptions_edited=False)
    status_write(result)
    print(json.dumps(result,indent=2))
    if not result['verified']:
        raise ValueError('Verification incomplete or failed; guard kept enabled. On-demand reconnection/TUN interception can prevent conclusive physical evidence')


def restore_after(args):
    m=installed_manifest()
    time.sleep(args.seconds)
    run(['/usr/sbin/scutil','--nc','start',m['vpn_service']],user=m,check=False)



def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('discover'); p.add_argument('--offline',action='store_true')
    p=sub.add_parser('setup-helper');p.add_argument('--app',required=True)
    p=sub.add_parser('plan');p.add_argument('--output',required=True);p.add_argument('--chain-exit',action='append');p.add_argument('--direct-socks5',action='append')
    p=sub.add_parser('merge-profile');p.add_argument('--input',required=True);p.add_argument('--output',required=True)
    p=sub.add_parser('install');p.add_argument('--plan',required=True);p.add_argument('--profile-applied',action='store_true')
    sub.add_parser('status');sub.add_parser('sync');sub.add_parser('daemon')
    p=sub.add_parser('verify');p.add_argument('--fault-test',action='store_true')
    p=sub.add_parser('restore-after',help=argparse.SUPPRESS);p.add_argument('--seconds',type=int,choices=range(1,61),required=True)
    p=sub.add_parser('uninstall');p.add_argument('--remove-protection',action='store_true')
    args=parser.parse_args()
    if args.action=='discover':
        require_mac();u=login_user();ports=provider_rows(u['uid'])
        result=dict(uid=u['uid'],listener_ports=sorted({r[2] for r in ports}),snapshot_present=snapshot_path(u['home']).exists(),
                    legacy_guard_present=Path('/Library/LaunchDaemons/local.shadowrocket.egress-guard.plist').exists())
        if not args.offline:
            result['proxy'],result['observed_exit']=discover_proxy(u['uid'])
        print(json.dumps(result,indent=2))
    elif args.action=='plan':plan(args)
    elif args.action=='install':install(args)
    elif args.action=='setup-helper':setup_helper(args)
    elif args.action=='merge-profile':merge(args)
    elif args.action=='daemon':daemon()
    elif args.action=='sync':synchronize(installed_manifest())
    elif args.action=='status':status()
    elif args.action=='verify':verify(args)
    elif args.action=='restore-after':restore_after(args)
    elif args.action=='uninstall':uninstall(args)


if __name__=='__main__':
    try:
        main()
    except (Exception,KeyboardInterrupt) as error:
        print('Not completed: '+str(error),file=sys.stderr)
        print('No global PF disable or automatic unrestricted fallback is issued. Installation/removal may be partial; inspect status before retrying.',file=sys.stderr)
        sys.exit(1)
