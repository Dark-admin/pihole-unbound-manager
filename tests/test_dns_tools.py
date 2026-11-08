import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]


class DnsToolsTests(unittest.TestCase):
    def shell(self, code, **variables):
        return subprocess.run(
            ['bash', '-c', "source <(sed '/^COMMAND=/,$d' nexo-dns.sh)\n" + code],
            cwd=ROOT, env=dict(os.environ, NO_COLOR='1', **variables),
            capture_output=True, text=True, timeout=12,
        )

    def test_health_rejects_null_blocking_address(self):
        result = self.shell(r'''
dig() { printf ';; ->>HEADER<<- status: NOERROR\nexample.com. 2 IN A 0.0.0.0\n'; }
dns_healthy 53
''')
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_health_rejects_private_address_for_public_probe(self):
        result = self.shell(r'''
dig() { printf ';; ->>HEADER<<- status: NOERROR\nexample.com. 2 IN A 192.168.1.7\n'; }
dns_healthy 53
''')
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_transport_failure_does_not_count_as_blocked(self):
        result = self.shell(r'''
clear_screen() { :; }
dig() { return 9; }
pause() { :; }
FTL_DB=/nonexistent
AGH_LOG=/nonexistent
ENGINE=pihole
IS_VPS=0
health_check
''')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn('✓ doubleclick.net bloqueado', result.stdout)

    def test_prewarm_selects_active_engine_and_checks_dns_rcode(self):
        with tempfile.TemporaryDirectory() as folder:
            conf = Path(folder, 'nexo.conf')
            conf.write_text('ENGINE=adguard\n', encoding='utf-8')
            log = Path(folder, 'querylog.json')
            now = datetime.now(timezone.utc).isoformat()
            rows = [
                {'T': now, 'QH': 'active.example', 'QT': 'AAAA', 'Result': {'IsFiltered': False}},
                {'T': now, 'QH': 'blocked.example', 'QT': 'A', 'Result': {'IsFiltered': True}},
                {'T': '2000-01-01T00:00:00Z', 'QH': 'old.example', 'QT': 'A'},
            ]
            log.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
            result = self.shell(r'''
CONF=$TEST_CONF; AGH_LOG=$TEST_LOG; FTL_DB=$TEST_CONF; UNBOUND_CONF=/nonexistent
systemctl() { [[ ${*: -1} == AdGuardHome ]]; }
pihole-FTL() { printf 'wrong.example|A\n'; }
dig() {
  printf 'sent: %s\n' "$*" >&2
  printf ';; ->>HEADER<<- status: SERVFAIL\n'
}
sleep() { :; }
prewarm_cache 4 7
''', TEST_CONF=str(conf), TEST_LOG=str(log))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('precalentados: 0', result.stdout)
        self.assertIn('fallidos: 1', result.stdout)
        self.assertIn('-q active.example -t AAAA', result.stderr)
        self.assertNotRegex(result.stderr, r'wrong\.example|blocked\.example|old\.example')

    def test_generated_prewarm_is_valid_bash(self):
        result = self.shell('render_prewarm_script | bash -n; render_prewarm_script')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('prewarm_cache "$@"', result.stdout)
        subprocess.run(['bash', '-n'], input=result.stdout, text=True, check=True)

    def test_bench_reports_separate_phases_and_percentiles(self):
        with tempfile.TemporaryDirectory() as folder:
            names = Path(folder, 'names')
            names.write_text('example.com A\n', encoding='ascii')
            result = self.shell(r'''
dig() {
  printf ';; ->>HEADER<<- status: NOERROR\nexample.com. 60 IN A 192.0.2.1\n'
  printf ';; Query time: 12 msec\n'
}
sleep() { :; }
bench_dns --json --layer filter --samples 2 --names "$TEST_NAMES"
''', TEST_NAMES=str(names))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        first, repeated = report['results']
        self.assertEqual((first['phase'], first['queries']), ('first_pass', 1))
        self.assertEqual((repeated['phase'], repeated['queries']), ('repeat', 2))
        self.assertEqual(first['p95_ms'], 12)
        self.assertEqual(repeated['noerror'], 2)

    def test_bench_rejects_option_like_query_names_without_querying(self):
        with tempfile.TemporaryDirectory() as folder:
            names = Path(folder, 'names')
            names.write_text('@1.1.1.1 A\n', encoding='ascii')
            result = self.shell(r'''
dig() { echo 'unexpected query'; }
bench_dns --json --names "$TEST_NAMES"
''', TEST_NAMES=str(names))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('unexpected query', result.stdout)

    def test_unbound_standard_referral_profile_keeps_dnssec(self):
        with tempfile.TemporaryDirectory() as folder:
            conf = Path(folder, 'unbound.conf')
            result = self.shell(r'''
UNBOUND_CONF=$TEST_UNBOUND; MODEL=fixture; OS_NAME=fixture
detect_hw() { RAM_MB=900 CORES=4 THREADS=2 MSG=32m RRSET=64m KEYC=8m NEG=2m SLABS=2; }
find_root_hints() { :; }
prune_unsupported() { :; }
parse_optimize_args --referral standard --min-ttl 0 && write_unbound_conf
''', TEST_UNBOUND=str(conf))
            self.assertEqual(result.returncode, 0, result.stderr)
            content = conf.read_text(encoding='utf-8')
        self.assertIn('harden-referral-path: no', content)
        self.assertIn('cache-min-ttl: 0', content)
        self.assertIn('harden-dnssec-stripped: yes', content)
        self.assertIn('module-config: "validator iterator"', content)

    def test_unbound_reload_retains_cache_only_with_compatible_config(self):
        with tempfile.TemporaryDirectory() as folder:
            old = Path(folder, 'old.conf')
            new = Path(folder, 'new.conf')
            shared = 'server:\n  interface: 127.0.0.1\n  port: 5335\n  num-threads: 2\n'
            old.write_text(shared + '  harden-referral-path: yes\n', encoding='ascii')
            new.write_text(shared + '  harden-referral-path: no\n', encoding='ascii')
            code = r'''
UNBOUND_CONF=$TEST_NEW
systemctl() { [[ $1 == is-active ]]; }
unbound-control() { :; }
timeout() { printf '%s\n' "$*"; }
unbound_reload_if_compatible "$TEST_OLD"
'''
            result = self.shell(code, TEST_OLD=str(old), TEST_NEW=str(new))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('unbound-control reload_keep_cache', result.stdout)
            new.write_text(shared.replace('5335', '5533'), encoding='ascii')
            result = self.shell(code, TEST_OLD=str(old), TEST_NEW=str(new))
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertNotIn('reload_keep_cache', result.stdout)


if __name__ == '__main__':
    unittest.main()
