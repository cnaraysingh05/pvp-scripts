"""Portable failure-path tests; no competition traffic or host security changes."""
import contextlib
import copy
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pvp_core


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


checks = module('service_checks', 'checks/check_services.py')
recon = module('red_recon', 'red/recon.py')
compare = module('baseline_diff', 'tools/baseline_diff.py')
backup = module('config_backup', 'blue/linux/config_backup.py')


class ScopeTests(unittest.TestCase):
    def scope(self, data, purpose='offense'):
        with patch('pvp_core.load_json', return_value=data):
            return pvp_core.scope_targets('unused', purpose)

    def test_unknowns_fail_closed(self):
        for target in ['172.16.XX.50', 'example.com', '1.2.3.4;id', 'fe80::1%en0']:
            with self.subTest(target=target), self.assertRaises(ValueError): pvp_core.literal_ip(target)

    def test_scope_requires_confirmation(self):
        with self.assertRaises(ValueError): self.scope({'confirmed': False})

    def test_router_kali_and_cidr_rejected(self):
        for target in ['172.16.1.1', '172.16.1.2', '172.16.1.0/24', '127.0.0.50']:
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.scope({'confirmed': True, 'own_targets': [], 'opponent_targets': [target]})

    def test_own_opponent_overlap_rejected(self):
        with self.assertRaises(ValueError): self.scope({'confirmed': True, 'own_targets': ['172.16.1.50'], 'opponent_targets': ['172.16.1.50']})

    def test_exact_target(self):
        self.assertEqual(self.scope({'confirmed': True, 'own_targets': ['172.16.1.50'], 'opponent_targets': ['172.16.2.50']}), {'172.16.2.50'})

    def test_private_unique_runs_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            one, two = [pvp_core.private_run_dir(d, 'same') for _ in range(2)]
            self.assertNotEqual(one, two)
            self.assertEqual(one.stat().st_mode & 0o777, 0o700)
            pvp_core.write_json(one/'x.json', {'ok': True})
            with self.assertRaises(FileExistsError): pvp_core.write_json(one/'x.json', {})


class CheckTests(unittest.TestCase):
    def item(self):
        return {'name': 'web', 'type': 'http', 'host': '192.0.2.52', 'port': 80,
                'path': '/', 'status': 200, 'contains': 'EXPECTED', 'tls': False}

    def test_scope_and_schema(self):
        with self.assertRaises(ValueError): checks.validate([self.item()], {'192.0.2.54'})
        bad = self.item(); bad['port'] = True
        with self.assertRaises(ValueError): checks.validate([bad], {'192.0.2.52'})
        bad = self.item(); bad['host_header'] = 'safe\r\nInjected: x'
        with self.assertRaises(ValueError): checks.validate([bad], {'192.0.2.52'})

    def test_duplicate_names(self):
        with self.assertRaises(ValueError): checks.validate([self.item(), self.item()], {'192.0.2.52'})

    def test_http_status_alone_is_insufficient(self):
        with patch.object(checks.http.client, 'HTTPConnection') as factory:
            response = factory.return_value.getresponse.return_value
            response.status = 200; response.read.return_value = b'wrong page'
            self.assertFalse(checks.check(self.item(), 5)[0])
            response.read.return_value = b'EXPECTED'
            self.assertTrue(checks.check(self.item(), 5)[0])
            response.status = 302
            self.assertFalse(checks.check(self.item(), 5)[0])
            self.assertEqual(factory.return_value.request.call_count, 3)

    def test_http_body_limit(self):
        with patch.object(checks.http.client, 'HTTPConnection') as factory:
            factory.return_value.getresponse.return_value.read.return_value = b'a' * 1048577
            self.assertFalse(checks.check(self.item(), 5)[0])

    def test_plan_does_not_contact_host(self):
        with tempfile.TemporaryDirectory() as d:
            config, scope = Path(d)/'checks.json', Path(d)/'scope.json'
            config.write_text(json.dumps([self.item()]))
            scope.write_text(json.dumps({'confirmed': True, 'own_targets': ['192.0.2.52'], 'opponent_targets': []}))
            with patch.object(sys, 'argv', ['check_services', '--config', str(config), '--scope', str(scope)]), patch.object(checks, 'check') as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(checks.main(), 0); run.assert_not_called()

    def test_dns_exact_answer(self):
        item = {'type': 'dns', 'host': '192.0.2.52', 'port': 53, 'query': 'test.example', 'expected': '192.0.2.1', 'transport': 'udp'}
        with patch.object(checks, 'command', return_value={'returncode': 0, 'stdout': '192.0.2.10\n', 'stderr': ''}):
            self.assertFalse(checks.native_check(item, 5, '.', '')[0])

    def test_password_not_in_argv_and_private_authfile(self):
        item = {'type': 'smb', 'host': '192.0.2.51', 'port': 445, 'user': 'user', 'domain': 'DOMAIN', 'share': 'data', 'contains': 'test.txt'}
        with tempfile.TemporaryDirectory() as d, patch.object(checks, 'command', return_value={'returncode': 0, 'stdout': 'test.txt', 'stderr': ''}) as run:
            self.assertTrue(checks.native_check(item, 5, d, 'SECRET-value')[0])
            argv = run.call_args.args[0]
            self.assertNotIn('SECRET-value', ' '.join(argv))
            self.assertEqual((Path(d)/'smb-auth').stat().st_mode & 0o777, 0o600)

    def test_database_failure_not_pass(self):
        item = {'type': 'postgres', 'host': '192.0.2.53', 'port': 5432, 'user': 'user', 'database': 'db'}
        with tempfile.TemporaryDirectory() as d, patch.object(checks, 'command', return_value={'returncode': 2, 'stdout': '1', 'stderr': 'fail'}):
            self.assertFalse(checks.native_check(item, 5, d, 'secret')[0])

    def test_plaintext_ldap_rejected(self):
        item = {'name': 'ldap', 'type': 'ldap', 'host': '192.0.2.50', 'port': 389, 'bind_dn': 'user', 'base_dn': 'DC=example', 'contains': 'DC=example', 'tls': 'none'}
        with self.assertRaises(ValueError): checks.validate([item], {'192.0.2.50'})

    def test_missing_tool_is_failure(self):
        with patch.object(checks.shutil, 'which', return_value=None):
            self.assertFalse(checks.check({'type': 'ssh'}, 5)[0])


class ReconTests(unittest.TestCase):
    def test_no_shell_or_broad_scripts(self):
        args = recon.build_argv('192.0.2.50', 'windows', Path('/tmp/run/nmap'))
        self.assertEqual(args[-1], '192.0.2.50')
        self.assertNotIn('-A', args)
        self.assertNotIn('--script=vuln', args)
        self.assertIn('--host-timeout', args)

    def test_grace_gate_precedes_execution(self):
        with patch.object(sys, 'argv', ['recon', '--scope', 'unused', '--target', '192.0.2.50', '--run']), patch.object(recon, 'scope_targets', return_value={'192.0.2.50'}), patch.object(recon, 'command') as run:
            with self.assertRaises(ValueError): recon.main()
            run.assert_not_called()

    def test_unlisted_target_rejected(self):
        with patch.object(sys, 'argv', ['recon', '--scope', 'unused', '--target', '192.0.2.51']), patch.object(recon, 'scope_targets', return_value={'192.0.2.50'}):
            with self.assertRaises(ValueError): recon.main()


class DiffTests(unittest.TestCase):
    def test_order_and_timestamp_do_not_hide_changes(self):
        a = {'UTC': 'old', 'Users': [{'Name': 'a'}, {'Name': 'b'}]}
        b = {'UTC': 'new', 'Users': [{'Name': 'b'}, {'Name': 'a'}]}
        self.assertEqual(compare.diff(compare.normalize(a), compare.normalize(b)), [])
        b['Users'].append({'Name': 'intruder'})
        self.assertTrue(compare.diff(compare.normalize(a), compare.normalize(b)))

    def test_collection_errors_visible(self):
        self.assertTrue(compare.diff({'Users': ['a']}, {'Users': {'Error': 'denied'}}))


class BackupTests(unittest.TestCase):
    def test_flag_and_symlink_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve(); (root/'flag.txt').write_text('flag')
            (root/'real.conf').write_text('config'); (root/'link.conf').symlink_to(root/'real.conf')
            with patch.object(backup, 'ALLOWED', (root,)):
                with self.assertRaises(ValueError): backup.regular_config(root/'flag.txt')
                with self.assertRaises(ValueError): backup.regular_config(root/'link.conf')
                self.assertTrue(backup.regular_config(root/'real.conf'))

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError): backup.regular_config(Path('/etc/ssh/../shadow'))


if __name__ == '__main__': unittest.main(verbosity=2)
