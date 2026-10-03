"""Regresiones de puertos, confianza y comprobaciones DNS; sin tocar /etc."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FirewallTests(unittest.TestCase):
    def shell(self, code):
        env = dict(os.environ, NO_COLOR="1", TERM="xterm")
        result = subprocess.run(
            ["bash", "-c", "source <(sed '/^COMMAND=/,$d' nexo-dns.sh)\n" + code],
            cwd=str(ROOT), env=env, text=True, capture_output=True, timeout=10)
        return result

    def test_pihole_all_civetweb_ports_and_deduplication(self):
        result = self.shell('''
ENGINE=pihole
ph_get() { echo '"80o,443os,[::]:80o,[::]:443os,192.168.1.10:8443s"'; }
engine_fw_ports || exit 1
echo "$FW_TCP|$FW_UDP"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "53,80,443,5335,8080,8443|53,5335")

    def test_missing_pihole_config_covers_fallbacks(self):
        result = self.shell('ENGINE=pihole; ph_get() { :; }; engine_fw_ports; echo "$FW_TCP"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "53,80,443,5335,8080,8443")

    def test_malformed_port_fails_closed_without_executing_it(self):
        result = self.shell('ENGINE=pihole; ph_get() { echo "80o,invalid"; }; engine_fw_ports')
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_ports_rejected(self):
        for port in ("0", "65536", "not-a-port"):
            result = self.shell('fw_port_list "{}"'.format(port))
            self.assertNotEqual(result.returncode, 0)

    def test_only_connected_private_networks_are_trusted(self):
        result = self.shell('''
FW_TRUST_CONF=/nonexistent/nexo-test
ip() { printf '192.168.1.0/24 dev eth0 proto kernel scope link\n100.64.0.0/10 dev tailscale0 scope link\n203.0.113.0/24 dev eth1 scope link\n'; }
fw_trusted_networks || exit 1
echo "$FW_V4|$FW_V6"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "192.168.1.0/24|fe80::/10")

    def test_trust_file_cannot_execute_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trusted"
            marker = Path(directory) / "executed"
            path.write_text('IPV4=$(touch {})\n'.format(marker))
            result = self.shell('FW_TRUST_CONF="{}"; fw_trusted_networks'.format(path))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_dns_servfail_exit_zero_is_not_healthy(self):
        result = self.shell("dig() { echo ';; ->>HEADER<<- status: SERVFAIL'; return 0; }; dns_healthy 53")
        self.assertNotEqual(result.returncode, 0)

    def test_dns_noerror_without_answer_is_not_healthy(self):
        result = self.shell("dig() { echo ';; ->>HEADER<<- status: NOERROR'; }; dns_healthy 53")
        self.assertNotEqual(result.returncode, 0)

    def test_dns_requires_actual_answer(self):
        result = self.shell("dig() { printf ';; ->>HEADER<<- status: NOERROR\nexample.com. 60 IN A 192.0.2.1\n'; }; dns_healthy 53")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_adguard_encrypted_dns_ports_are_covered(self):
        result = self.shell('''
ENGINE=adguard; AGH_YAML=README.md; AGH_READY=1
agh_get() {
  case "$2" in enabled) echo true ;; port_https) echo 443 ;;
    port_dns_over_tls) echo 853 ;; port_dns_over_quic) echo 784 ;;
    port_dnscrypt) echo 5443 ;; esac
}
engine_fw_ports || exit 1
echo "$FW_TCP|$FW_UDP"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "53,80,443,853,5335,5443,8080|53,784,5335,5443")

    def test_leading_zero_port_is_decimal(self):
        result = self.shell('fw_port_list 08')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "8")

    def test_audit_uses_active_engine_without_loading_panel(self):
        result = self.shell('''
ENGINE=pihole
systemctl() { echo "$*" >&2; return 0; }
dns_healthy() { return 0; }
unbound-checkconf() { echo 127.0.0.1; }
fw_active() { return 0; }
sshd() { printf 'passwordauthentication no\\npermitrootlogin no\\n'; }
apt() { echo Listing; }
security_audit
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("is-active --quiet pihole-FTL", result.stderr)
        self.assertIn("0 fallo(s)", result.stdout)


if __name__ == "__main__":
    unittest.main()
