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
ph_get() { echo '"+80o,443os,[::]:80o,[::]:443os,192.168.1.10:8443s"'; }
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

    def test_adguard_http3_adds_the_configured_https_port_to_udp(self):
        result = self.shell('''
ENGINE=adguard; AGH_READY=1
AGH_YAML=$(mktemp)
trap 'rm -f -- "$AGH_YAML"' EXIT
printf 'dns:\\n  serve_http3: true # DoH3\\ntls:\\n  enabled: true # TLS\\n  port_https: 8443 # custom\\n' > "$AGH_YAML"
engine_fw_ports || exit 1
echo "$FW_TCP|$FW_UDP"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "53,80,5335,8080,8443|53,5335,8443")

    def test_adguard_rejects_an_out_of_range_encrypted_port(self):
        result = self.shell('''
ENGINE=adguard; AGH_YAML=README.md; AGH_READY=1
agh_get() {
  case "$2" in enabled) echo true ;; port_dns_over_quic) echo 65536 ;; esac
}
engine_fw_ports
''')
        self.assertNotEqual(result.returncode, 0)

    def test_firewall_command_reports_failed_application(self):
        result = self.shell('''
need() { return 0; }
clear_screen() { :; }
yes_no() { return 0; }
pause() { return 0; }
engine_fw_ports() { :; }
fw_trusted_networks() { FW_V4=""; FW_V6=""; }
install_firewall_quiet() { return 1; }
install_firewall
''')
        self.assertNotEqual(result.returncode, 0)

    def test_failed_firewall_backup_aborts_before_applying_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.shell('''
TEST_DIR="{}"
FW_NFT="$TEST_DIR/firewall.nft"
FW_UNIT="$TEST_DIR/firewall.service"
FW_TRUST_CONF="$TEST_DIR/trusted"
FW_NFTABLES_CONF="$TEST_DIR/nftables.conf"
FW_NFTABLES_LOAD="$TEST_DIR/nftables-nexo.conf"
FW_NFTABLES_DROPIN="$TEST_DIR/90-nexo-dns.conf"
BACKUP_ROOT="$TEST_DIR/backups"
printf 'existing rules\n' > "$FW_NFT"
ENGINE=pihole
ph_get() {{ echo 80; }}
nft() {{
  if [[ "$1" == -f ]]; then touch "$TEST_DIR/applied"; fi
}}
systemctl() {{ return 0; }}
dns_healthy() {{ return 0; }}
cp() {{ return 1; }}
install_firewall_quiet
'''.format(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / "firewall.nft").read_text(), "existing rules\n")
            self.assertFalse((root / "applied").exists())

    def test_leading_zero_port_is_decimal(self):
        result = self.shell('fw_port_list 08')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "8")

    def test_audit_uses_active_engine_without_loading_panel(self):
        result = self.shell('''
ENGINE=pihole
systemctl() { echo "$*" >&2; return 0; }
dns_healthy() { return 0; }
unbound-checkconf() {
  case "$2" in interface) echo 127.0.0.1 ;; interface-automatic) echo no ;; esac
}
ss() {
  printf 'udp UNCONN 0 0 127.0.0.1:5335 0.0.0.0:* users:(("unbound",pid=40,fd=5))\n'
  printf 'tcp LISTEN 0 0 [::1]:5335 [::]:* users:(("unbound",pid=40,fd=6))\n'
}
fw_active() { return 0; }
sshd() { printf 'passwordauthentication no\\npermitrootlogin no\\n'; }
apt() { echo Listing; }
security_audit
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("is-active --quiet pihole-FTL", result.stderr)
        self.assertIn("0 fallo(s)", result.stdout)

    def test_audit_rejects_unbound_automatic_interfaces(self):
        result = self.shell('''
ENGINE=pihole
systemctl() { return 0; }
dns_healthy() { return 0; }
unbound-checkconf() {
  case "$2" in interface) echo 127.0.0.1 ;; interface-automatic) echo yes ;; esac
}
fw_active() { return 0; }
ss() {
  printf 'udp UNCONN 0 0 127.0.0.1:5335 0.0.0.0:* users:(("unbound",pid=40,fd=5))\n'
}
sshd() { printf 'passwordauthentication no\npermitrootlogin no\n'; }
apt() { echo Listing; }
security_audit
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("interface-automatic", result.stdout)

    def test_audit_rejects_unbound_wildcard_socket_on_another_port(self):
        result = self.shell('''
ENGINE=pihole
systemctl() { return 0; }
dns_healthy() { return 0; }
unbound-checkconf() {
  case "$2" in interface) echo 127.0.0.1 ;; interface-automatic) echo no ;; esac
}
fw_active() { return 0; }
ss() {
  printf 'udp UNCONN 0 0 127.0.0.1:5335 0.0.0.0:* users:(("unbound",pid=40,fd=5))\n'
  printf 'tcp LISTEN 0 0 [::]:5533 [::]:* users:(("unbound",pid=40,fd=6))\n'
}
sshd() { printf 'passwordauthentication no\npermitrootlogin no\n'; }
apt() { echo Listing; }
security_audit
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("[::]:5533", result.stdout)


if __name__ == "__main__":
    unittest.main()
