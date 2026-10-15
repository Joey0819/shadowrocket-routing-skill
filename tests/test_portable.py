"""No sudo, live profile edits, VPN stops or PF activation. Synthetic metadata only."""
import copy
import datetime
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=ROOT/'skills/shadowrocket-ai-routing/scripts'
sys.path.insert(0,str(SCRIPTS))
import core
import portable_guard as guard


def manifest():
    # Deliberately synthetic allocation coverage, never used for real activation.
    v4=[str(ipaddress.ip_network(str(i)+'.0.0.0/8')) for i in (1,2,5,8,9,11,12,13)]
    v4 += [str(n) for n in list(ipaddress.ip_network('14.0.0.0/8').subnets(new_prefix=24))[:1000]]
    v6=[str(n) for n in list(ipaddress.ip_network('2400::/32').subnets(new_prefix=48))[:100]]
    records=[dict(subscription='upstream',name='A',host='46.1.1.1',port='24443',type='VLESS'),
             dict(subscription='local',name='B',host='45.1.1.1',port='18080',type='Socks5')]
    return dict(version=core.VERSION,uid=1003,gid=20,home='/Users/test-user',proxy='http://127.0.0.1:18433',
                vpn_service='00000000-0000-0000-0000-000000000001',physical_interface='en1',
                observed_at=core.now().isoformat(),observed_exit='47.1.1.1',records=records,
                addresses={'46.1.1.1':['46.1.1.1'],'45.1.1.1':['45.1.1.1']},
                excluded_hosts=['45.1.1.1'],excluded_addresses=['45.1.1.1'],direct_socks5_hosts=[],
                node_fingerprint=core.node_fingerprint(records),snapshot='/private/not-used.json',
                policy=dict(source=core.APNIC,source_sha256='a'*64,prepared_at=core.now().isoformat(),
                            cn_networks={'4':v4,'6':v6},protected_addresses={h:['8.8.8.8'] for h in core.CORE_AI}))


class BoundaryTests(unittest.TestCase):
    def setUp(self):self.m=manifest()

    def test_nondefault_uid_port_and_interface_validate(self):
        self.assertEqual(core.validate_manifest(self.m)['proxy'],'http://127.0.0.1:18433')

    def test_ai_deny_precedes_every_physical_exception(self):
        text=core.render(self.m,['lo0','utun9','en1','awdl0'])
        for label in ('SRP_proxy','SRP_CN_direct','SRP_LAN4','SRP_DNS_deny'):
            self.assertLess(text.index('SRP_AI_deny'),text.index(label))
        self.assertEqual(text.splitlines()[-2:],['block drop out quick all label "SRP_block_out"','block drop in quick all label "SRP_block_in"'])
        self.assertNotIn('pass out quick all',text)
        self.assertNotIn('3478',text) # no unrelated globally allowed UDP/Tailscale exception

    def test_chained_exit_has_no_direct_exception(self):
        text=core.render(self.m,['lo0','utun9','en1'])
        self.assertIn('to 46.1.1.1 port 24443',text)
        self.assertNotIn('to 45.1.1.1 port 18080',text)
        self.assertTrue(all('if-bound' in l for l in text.splitlines() if 'SRP_proxy' in l or 'SRP_CN_direct' in l))

    def test_new_node_and_port_updates_are_exact_without_mutating_source(self):
        old=copy.deepcopy(self.m)
        rows=copy.deepcopy(self.m['records'])
        rows[0]['port']='24444'
        rows.append(dict(rows[0],host='48.1.1.1',name='new subscription',subscription='new'))
        changed=guard.candidate_sync(self.m,rows,lambda h,p:[h])
        text=core.render(changed,['lo0'])
        self.assertIn('to 48.1.1.1 port 24444',text)
        self.assertEqual(self.m,old)

    def test_deletion_removes_allowed_peer(self):
        self.m['records'].append(dict(self.m['records'][0],host='48.1.1.1',name='extra'))
        self.m['addresses']['48.1.1.1']=['48.1.1.1']
        changed=guard.candidate_sync(self.m,self.m['records'][:2])
        self.assertNotIn('48.1.1.1',changed['addresses'])

    def test_chain_exit_change_or_removal_is_rejected(self):
        for rows in (self.m['records'][:1],[self.m['records'][0],dict(self.m['records'][1],port='18081')]):
            with self.assertRaises(ValueError):guard.candidate_sync(self.m,rows)

    def test_new_socks5_requires_chain_classification(self):
        rows=self.m['records']+[dict(self.m['records'][1],host='48.1.1.1')]
        with self.assertRaises(ValueError):guard.candidate_sync(self.m,rows,lambda h,p:[h])

    def test_failed_or_private_resolution_does_not_create_candidate(self):
        rows=self.m['records']+[dict(self.m['records'][0],host='new.example.org')]
        for resolver in (lambda h,p:[],lambda h,p:['127.0.0.1']):
            with self.assertRaises(ValueError):guard.candidate_sync(self.m,rows,resolver)
        with self.assertRaises(RuntimeError):
            guard.candidate_sync(self.m,rows,lambda h,p:(_ for _ in ()).throw(RuntimeError('offline')))

    def test_shared_ai_or_excluded_exit_address_rejected(self):
        for address in ('8.8.8.8','45.1.1.1'):
            self.m['addresses']['46.1.1.1']=[address]
            with self.assertRaises(ValueError):core.validate_manifest(self.m)

    def test_ai_hostname_is_not_an_entry(self):
        rows=self.m['records']+[dict(self.m['records'][0],host='api.chatgpt.com')]
        with self.assertRaises(ValueError):guard.candidate_sync(self.m,rows,lambda h,p:['49.1.1.1'])

    def test_unsafe_ports_credentials_and_unknown_protocol_rejected(self):
        for changed in (dict(port='0'),dict(port='65536'),dict(port='53'),dict(port='853'),dict(port='443;pass all'),
                        dict(port='1-65535'),dict(password='fixture-only'),dict(type='UNKNOWN'),dict(host='127.0.0.1')):
            with self.subTest(changed=changed),self.assertRaises(RuntimeError):
                core.validate_node_records([dict(self.m['records'][0],**changed)])

    def test_overbroad_domestic_allowlist_rejected(self):
        self.m['policy']['cn_networks']['4'][0]='0.0.0.0/0'
        with self.assertRaises(ValueError):core.validate_manifest(self.m)

    def test_expired_cn_policy_closes_domestic_but_keeps_ai_deny(self):
        self.m['policy']['prepared_at']=(core.now()-datetime.timedelta(days=31)).isoformat()
        text=core.render(self.m,['lo0','en1'])
        self.assertNotIn('label "SRP_CN_direct"',text)
        self.assertIn('SRP_AI_deny',text)
        self.assertIn('SRP_block_out',text)

    def test_root_manifest_addresses_and_public_listener_rejected(self):
        for change in (dict(uid=0),dict(proxy='http://0.0.0.0:18433'),dict(vpn_service='x;pass'),dict(physical_interface='en0;pass')):
            with self.assertRaises(ValueError):core.validate_manifest(dict(self.m,**change))

    def test_missing_ai_baseline_rejected(self):
        del self.m['policy']['protected_addresses']['claude.ai']
        with self.assertRaises(ValueError):core.validate_manifest(self.m)

    def test_snapshot_owner_mode_age_partial_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'snapshot.json'
            value=dict(version=1,status='ready',observed_at=core.now().isoformat(),unmatched_subscription_count=0,records=self.m['records'])
            core.atomic(p,json.dumps(value))
            self.assertEqual(len(core.read_snapshot(p,os.getuid())),2)
            p.chmod(0o644)
            with self.assertRaises(ValueError):core.read_snapshot(p,os.getuid())
            p.chmod(0o600)
            for changed in (dict(status='schema_unconfirmed'),dict(unmatched_subscription_count=1),
                            dict(observed_at=(core.now()-datetime.timedelta(minutes=3)).isoformat())):
                core.atomic(p,json.dumps(dict(value,**changed)))
                with self.assertRaises(ValueError):core.read_snapshot(p,os.getuid())
            link=Path(d)/'link';link.symlink_to(p)
            with self.assertRaises(OSError):core.read_snapshot(link,os.getuid())

    def test_listener_discovery_rejects_other_processes_and_public_bindings(self):
        text='p12\ncMacPacketTunnel\nu1003\nn127.0.0.1:18433\nn[::1]:18433\np13\ncother\nu1003\nn127.0.0.1:18000\np14\ncMacPacketTunnel\nu1003\nn*:19000\n'
        self.assertEqual(core.listener_candidates(text),[(12,1003,18433)])

    def test_install_requires_profile_confirmation_before_mutation(self):
        from argparse import Namespace
        with patch.object(guard,'require_root'),patch.object(guard,'preflight') as preflight:
            with self.assertRaises(ValueError):guard.install(Namespace(profile_applied=False))
            preflight.assert_not_called()

    def test_partial_snapshot_never_calls_apply(self):
        with patch.object(core,'read_snapshot',side_effect=ValueError('partial')),patch.object(guard,'apply') as apply:
            with self.assertRaises(ValueError):guard.synchronize(self.m)
            apply.assert_not_called()

    def test_same_inventory_does_not_reload_or_resolve(self):
        with tempfile.TemporaryDirectory() as d,patch.object(guard,'INSTALL',Path(d)),patch.object(core,'read_snapshot',return_value=self.m['records']),patch.object(guard,'sync_status_write'),patch.object(guard,'apply') as apply:
            self.assertEqual(guard.synchronize(self.m),self.m)
            apply.assert_not_called()

    def test_capture_parser_only_counts_outgoing_target(self):
        line='IP 192.168.1.10.54545 > 8.8.8.8.443: Flags [S]'
        self.assertTrue(guard.outgoing_to(line,'8.8.8.8',443))
        self.assertFalse(guard.outgoing_to(line,'8.8.8.8',80))
        self.assertFalse(guard.outgoing_to('IP 8.8.8.8.443 > 192.168.1.10.54545:','8.8.8.8'))

    def test_actual_macos_pf_syntax_without_activation(self):
        if sys.platform!='darwin':self.skipTest('macOS PF parser unavailable')
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'test.pf';p.write_text(core.render(self.m,['lo0','utun9','en1','awdl0','llw0']))
            guard.syntax(p)


    def test_ai_node_hostname_check_is_case_insensitive(self):
        rows=self.m['records']+[dict(self.m['records'][0],host='API.ChatGPT.COM')]
        with self.assertRaises(ValueError):guard.candidate_sync(self.m,rows,lambda h,p:['49.1.1.1'])
        with patch.object(guard.subprocess,'run') as run:
            with self.assertRaises(ValueError):guard.resolve_node('API.ChatGPT.COM',self.m['proxy'])
            run.assert_not_called()

    def test_dns_wire_bounds_id_and_public_answer_checks(self):
        import struct
        query=core.dns_query('node.example.org',1,123)
        head=struct.pack('!HHHHHH',123,0x8180,1,1,0,0)
        response=head+query[12:]+bytes([0xc0,0x0c])+struct.pack('!HHIH',1,1,60,4)+bytes([46,1,1,1])
        self.assertEqual(core.dns_answers(response,123),['46.1.1.1'])
        for bad in (response[:-1],response[:8],response[:2]+bytes([0x83,0x80])+response[4:]):
            with self.assertRaises(ValueError):core.dns_answers(bad,123)
        with self.assertRaises(ValueError):core.dns_answers(response,124)
        with self.assertRaises(ValueError):core.dns_answers(response[:-4]+bytes([127,0,0,1]),123)

    def test_node_dns_is_independent_of_proxy_and_never_plaintext(self):
        import struct
        calls=[]
        def request(args,**kw):
            self.assertIn('--noproxy',args)
            self.assertIn('https://223.5.5.5/dns-query',args)
            self.assertNotIn('--proxy',args)
            calls.append(args)
            wire=kw['input'];ident=int.from_bytes(wire[:2],'big')
            from types import SimpleNamespace
            return SimpleNamespace(returncode=0,stdout=struct.pack('!HHHHHH',ident,0x8180,1,1,0,0)+wire[12:]+bytes([0xc0,0x0c])+struct.pack('!HHIH',1,1,60,4)+bytes([46,1,1,1]))
        with patch.object(guard.subprocess,'run',side_effect=request):
            self.assertEqual(guard.resolve_node('node.example.org',self.m['proxy']),['46.1.1.1'])
        self.assertEqual(len(calls),2)


    def test_install_stages_root_runtime_and_preserves_stock_root_configuration(self):
        from argparse import Namespace
        import contextlib,io
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); install=root/'installed'; pf=root/'pf.conf'; plist=root/'guard.plist'
            original='\n'.join(guard.STOCK)+'\n';pf.write_text(original)
            m=copy.deepcopy(self.m);m['uid']=os.getuid();m['gid']=os.getgid()
            plan=root/'plan.json';core.atomic(plan,json.dumps(m))
            with patch.object(guard,'require_root'),patch.object(guard,'login_user',return_value={'uid':os.getuid()}), \
                 patch.object(guard,'machine_match'),patch.object(core,'read_snapshot',return_value=m['records']), \
                 patch.object(guard,'preflight'),patch.object(guard,'root_tree'),patch.object(guard,'syntax'), \
                 patch.object(guard,'ifaces',return_value=['lo0','en1']),patch.object(guard,'apply',return_value='fixture'), \
                 patch.object(guard,'run') as run,patch.object(guard,'INSTALL',install),patch.object(guard,'PFCONF',pf),patch.object(guard,'PLIST',plist), \
                 contextlib.redirect_stdout(io.StringIO()):
                guard.install(Namespace(profile_applied=True,plan=str(plan)))
            self.assertTrue(pf.read_text().startswith(original.rstrip()))
            self.assertIn('load anchor',pf.read_text())
            self.assertTrue((install/'core.py').exists())
            self.assertEqual((install/'portable_guard.py').stat().st_mode&0o777,0o600)
            program=plistlib.loads(plist.read_bytes())['ProgramArguments']
            self.assertEqual(program[1:],['-I',str(install/'portable_guard.py'),'daemon'])
            self.assertEqual(run.call_count,1)

    def test_activation_failure_does_not_uninstall_or_flush(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); install=root/'installed';pf=root/'pf.conf';plist=root/'guard.plist'
            pf.write_text('\n'.join(guard.STOCK)+'\n')
            m=copy.deepcopy(self.m);m['uid']=os.getuid();m['gid']=os.getgid()
            plan=root/'plan.json';core.atomic(plan,json.dumps(m))
            with patch.object(guard,'require_root'),patch.object(guard,'login_user',return_value={'uid':os.getuid()}), \
                 patch.object(guard,'machine_match'),patch.object(core,'read_snapshot',return_value=m['records']), \
                 patch.object(guard,'preflight'),patch.object(guard,'root_tree'),patch.object(guard,'syntax'), \
                 patch.object(guard,'ifaces',return_value=['lo0']),patch.object(guard,'apply',side_effect=RuntimeError('activation failed')), \
                 patch.object(guard,'run') as run,patch.object(guard,'INSTALL',install),patch.object(guard,'PFCONF',pf),patch.object(guard,'PLIST',plist):
                with self.assertRaises(RuntimeError):guard.install(Namespace(profile_applied=True,plan=str(plan)))
                run.assert_not_called()
            self.assertTrue((install/'guard.pf').exists())
            self.assertIn('SRP_block_out',(install/'guard.pf').read_text())


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.fragment=(ROOT/'skills/shadowrocket-ai-routing/assets/routing-fragment.conf').read_text()
        self.original='''# source\n[General]\nhttp-port = 18777\nsocks-port = 18778\ndns-server = system\n[Proxy Group]\nA = fallback,node1,node2\n[Rule]\nDOMAIN-SUFFIX,cn,DIRECT\nDOMAIN,custom.example,PROXY\nFINAL,DIRECT\n[Host]\nlocal.example = 192.168.1.2\n[URL Rewrite]\n^http://local http://other 302\n'''

    def test_only_general_and_rules_change_ports_and_groups_preserved(self):
        merged=core.merge_profile(self.original,self.fragment)
        old=core.profile_sections(self.original);new=core.profile_sections(merged)
        for section in ('Proxy Group','Host','URL Rewrite'):
            self.assertEqual(self.original[slice(*old[section])],merged[slice(*new[section])])
        self.assertIn('http-port = 18777',merged)
        self.assertIn('socks-port = 18778',merged)
        self.assertLess(merged.index('DOMAIN-SUFFIX,claude.ai,PROXY'),merged.index('DOMAIN-SUFFIX,cn,DIRECT'))
        self.assertIn('DOMAIN,custom.example,PROXY',merged)
        self.assertNotIn('FINAL,DIRECT',merged)
        self.assertEqual(merged.count('dns-server = https://223.5.5.5/dns-query#no-h3'),2) # regular + direct

    def test_duplicate_sections_fail_instead_of_overwriting(self):
        with self.assertRaises(ValueError):core.merge_profile(self.original+'\n[General]\n',self.fragment)

    def test_merge_is_idempotent_for_rules_and_general_values(self):
        a=core.merge_profile(self.original,self.fragment)
        b=core.merge_profile(a,self.fragment)
        for text in (a,b):
            self.assertEqual(text.count('FINAL,PROXY'),1)
            self.assertEqual(text.count('DOMAIN-SUFFIX,claude.ai,PROXY'),1)
        # Whitespace is insignificant; nonempty content should also be stable.
        self.assertEqual([l for l in a.splitlines() if l],[l for l in b.splitlines() if l])

    def test_sandbox_has_no_network_or_absolute_write_exception(self):
        path=ROOT/'skills/shadowrocket-ai-routing/assets/node-sync/entitlements.plist'
        ent=plistlib.loads(path.read_bytes())
        self.assertTrue(ent['com.apple.security.app-sandbox'])
        self.assertTrue(ent['com.apple.security.files.user-selected.read-only'])
        self.assertNotIn('com.apple.security.network.client',ent)
        self.assertFalse(any('absolute-path' in k for k in ent))


if __name__=='__main__':unittest.main(verbosity=2)
