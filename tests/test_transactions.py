"""Ejercita transacciones DNS con ficheros temporales y systemd simulado."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]

SETUP = r'''
source <(sed '/^COMMAND=/,$d' nexo-dns.sh)
CONF="$TEST_DIR/nexo-dns.conf"
UNBOUND_CONF="$TEST_DIR/pi-hole.conf"
PIHOLE_TOML="$TEST_DIR/pihole.toml"
AGH_YAML="$TEST_DIR/AdGuardHome.yaml"
AGH_BIN=/bin/true
AGH_DIR="$TEST_DIR"
BACKUP_ROOT="$TEST_DIR/backups"
FW_NFT="$TEST_DIR/firewall.nft"
FW_UNIT="$TEST_DIR/firewall.service"
FW_NFTABLES_LOAD="$TEST_DIR/nftables-load.conf"
FW_NFTABLES_DROPIN="$TEST_DIR/nftables-dropin.conf"
ENGINE=pihole
LISTEN_IP=192.0.2.2
PH_MAJOR=6
AGH_PRESENT=1
AGH_READY=1
RAM_MB=512
printf 'ENGINE=pihole\nUNBOUND_PORT=5335\n' > "$CONF"
printf 'server:\n  port: 5335\n' > "$UNBOUND_CONF"
printf 'pihole-config\n' > "$PIHOLE_TOML"
cat > "$AGH_YAML" <<'EOF'
users:
- name: admin
  password: '$2a$10$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
dns:
  port: 53
  upstream_dns:
  - 1.1.1.1
  bootstrap_dns: []
  fallback_dns:
  - 8.8.8.8
  upstream_dns_file: /private/upstreams
  bind_hosts:
  - 127.0.0.1
http:
  address: 127.0.0.1:80
querylog:
  interval: 24h
statistics:
  interval: 24h
EOF
for service in pihole-FTL AdGuardHome unbound; do
  touch "$TEST_DIR/$service.exists"
done
touch "$TEST_DIR/pihole-FTL.active" "$TEST_DIR/unbound.active" "$TEST_DIR/unbound.enabled"
detect_pihole() { :; }
detect_adguard() { :; }
detect_hw() { :; }
detect_os() { :; }
detect_platform() { :; }
clear_screen() { :; }
splash() { :; }
pause() { :; }
sleep() { :; }
yes_no() { return 0; }
fw_active() { return 1; }
resolved_conflicts() { return 1; }
port_taken_by_other() { return 1; }
unbound-checkconf() { return 0; }
apply_sysctl_dns() { :; }
dig() {
  if [[ "$*" == *dnssec-failed.org* ]]; then echo 'status: SERVFAIL'; else echo 'flags: qr ad;'; fi
}
systemctl() {
  local verb="$1" service="${@: -1}" p="$TEST_DIR/${@: -1}"
  shift
  case "$verb" in
    cat) [[ -f "$p.exists" ]] ;;
    is-active) [[ -f "$p.active" ]] ;;
    is-enabled)
      [[ -f "$p.exists" ]] || return 1
      if [[ -f "$p.enabled" ]]; then echo enabled; else echo disabled; return 1; fi ;;
    enable) touch "$p.enabled"; [[ "$1" != --now ]] || systemctl start "$service" ;;
    disable) rm -f "$p.enabled"; [[ "$1" != --now ]] || systemctl stop "$service" ;;
    stop) printf 'stop:%s\n' "$service" >> "$TEST_DIR/events"; rm -f "$p.active" ;;
    restart) systemctl stop "$service" && systemctl start "$service" ;;
    start)
      [[ -f "$p.exists" ]] || return 1
      if [[ "$service" == AdGuardHome ]] && grep -q '^  port: 5354$' "$AGH_YAML"; then return 1; fi
      printf 'start:%s\n' "$service" >> "$TEST_DIR/events"
      touch "$p.active" ;;
    *) return 1 ;;
  esac
}
'''


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)

    def shell(self, code):
        env = dict(os.environ, NO_COLOR="1", TERM="xterm", TEST_DIR=str(self.path))
        return subprocess.run(["bash", "-c", SETUP + code], cwd=ROOT, env=env,
                              text=True, capture_output=True, timeout=15)

    def state(self, service):
        return ((self.path / (service + ".active")).exists(),
                (self.path / (service + ".enabled")).exists())

    def test_failed_final_switch_probe_restores_previous_filter(self):
        result = self.shell(r'''
configure_engine() { echo target-configured > "$AGH_YAML"; systemctl start "$AGH_SVC"; }
dns_healthy() { ! grep -q 'target-configured' "$AGH_YAML"; }
switch_engine
''')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("ENGINE=pihole", (self.path / "nexo-dns.conf").read_text())
        self.assertEqual(self.state("pihole-FTL"), (True, False))
        self.assertEqual(self.state("AdGuardHome"), (False, False))
        self.assertIn("upstream_dns_file", (self.path / "AdGuardHome.yaml").read_text())

    def test_failed_adguard_dns_port_start_rolls_back(self):
        result = self.shell(r'''
ENGINE=adguard
systemctl start "$AGH_SVC"
ask() { echo 5354; }
dns_healthy() { return 0; }
change_pihole_port
''')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.state("AdGuardHome"), (True, False))
        self.assertIn("  port: 53\n", (self.path / "AdGuardHome.yaml").read_text())
        self.assertNotIn("5354", (self.path / "nexo-dns.conf").read_text())

    def test_cancelled_adguard_wizard_brings_back_pihole(self):
        result = self.shell(r'''
detect_adguard() { AGH_PRESENT=0; AGH_READY=0; [[ ! -f "$TEST_DIR/installed" ]] || AGH_PRESENT=1; }
fetch_and_run_installer() { touch "$TEST_DIR/installed"; systemctl enable --now "$AGH_SVC"; }
rm "$AGH_YAML"
install_adguard
''')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.state("pihole-FTL"), (True, False))
        self.assertEqual(self.state("AdGuardHome"), (False, False))

    def test_failed_full_install_restores_prior_services_and_configuration(self):
        result = self.shell(r'''
ask() { echo 2; }
apt-get() { return 0; }
write_unbound_conf() { printf 'server:\n  port: 9999\n' > "$UNBOUND_CONF"; }
dns_healthy() { return 1; }
do_install
''')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.state("pihole-FTL"), (True, False))
        self.assertEqual(self.state("AdGuardHome"), (False, False))
        self.assertEqual(self.state("unbound"), (True, True))
        self.assertEqual((self.path / "pi-hole.conf").read_text(), "server:\n  port: 5335\n")

    def test_restore_filters_invalid_backups_and_repoints_filter(self):
        result = self.shell(r'''
mkdir -p "$BACKUP_ROOT/valid" "$BACKUP_ROOT/firewall"
printf 'server:\n  port: 5533\n' > "$BACKUP_ROOT/valid/pi-hole.conf"
touch "$BACKUP_ROOT/firewall"
ask() { echo 1; }
configure_engine() { printf 'upstream=127.0.0.1#%s\n' "$UNBOUND_PORT" > "$PIHOLE_TOML"; }
dns_healthy() {
  case "$1" in
    5533) grep -q 'port: 5533' "$UNBOUND_CONF" ;;
    53) grep -q 'upstream=127.0.0.1#5533' "$PIHOLE_TOML" ;;
    *) return 1 ;;
  esac
}
backups_menu
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(") firewall", result.stdout)
        self.assertIn("port: 5533", (self.path / "pi-hole.conf").read_text())
        self.assertIn("#5533", (self.path / "pihole.toml").read_text())
        self.assertIn("UNBOUND_PORT=5533", (self.path / "nexo-dns.conf").read_text())

    def test_configure_adguard_clears_external_upstreams_and_preserves_admin(self):
        result = self.shell(r'''
configure_adguard
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        yaml = (self.path / "AdGuardHome.yaml").read_text()
        self.assertNotIn("/private/upstreams", yaml)
        self.assertNotIn("1.1.1.1", yaml)
        self.assertNotIn("8.8.8.8", yaml)
        self.assertIn("- 127.0.0.1:5335", yaml)
        self.assertIn("- name: admin\n  password: '$2a$10$", yaml)

    def test_adguard_uses_unbound_minimum_ttl_from_selected_profile(self):
        result = self.shell(r'''
printf '  cache-min-ttl: 0\n' >> "$UNBOUND_CONF"
configure_adguard
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('cache_ttl_min: 0', (self.path / 'AdGuardHome.yaml').read_text())

    def test_adguard_rejects_per_client_external_upstreams_before_writing(self):
        result = self.shell(r'''
cat >> "$AGH_YAML" <<'YAML'
clients:
  persistent:
    - name: test-client
      ids: [192.0.2.7]
      upstreams: [9.9.9.9]
YAML
configure_adguard
''')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('upstream_dns_file: /private/upstreams', (self.path / 'AdGuardHome.yaml').read_text())

    def test_resolved_restart_failure_is_reported(self):
        result = self.shell(r'''
source <(sed -n '/^fix_resolved()/,/^}/p' nexo-dns.sh |
  sed "s|/etc/systemd/resolved.conf.d|$TEST_DIR/resolved|g; s|/etc/resolv.conf|$TEST_DIR/resolv.conf|g")
resolved_conflicts() { return 1; }
systemctl() { return 1; }
fix_resolved "$TEST_DIR/resolved/no-stub.conf" "$TEST_DIR/resolv.conf"
''')
        self.assertTrue((self.path / 'resolved/no-stub.conf').is_file())
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn('Puerto 53 libre', result.stdout)

    def test_mutation_rejects_managed_firewall_missing_live_table(self):
        result = self.shell(r'''
FW_NFT="$TEST_DIR/firewall.nft"; FW_UNIT="$TEST_DIR/firewall.service"; FW_NFTABLES_DROPIN="$TEST_DIR/unused"
touch "$FW_NFT"
custom_operation() { echo 'operation ran'; }
dns_transaction 'pihole-FTL' custom_operation
''')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn('operation ran', result.stdout)

    def test_rollback_stops_pending_target_and_protects_old_port_before_start(self):
        result = self.shell(r'''
fw_active() { return 0; }
fw_snapshot() { :; }
fw_restore_snapshot() { echo firewall-restored >> "$TEST_DIR/events"; }
failed_change() {
  dns_touch_service pihole-FTL
  dns_touch_service "$AGH_SVC"
  txn_fw_changed=1
  systemctl stop pihole-FTL
  return 1
}
dns_transaction "pihole-FTL $AGH_SVC" failed_change
''')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        events = (self.path / 'events').read_text().splitlines()
        self.assertLess(events.index('stop:AdGuardHome'), events.index('firewall-restored'))
        self.assertLess(events.index('firewall-restored'), events.index('start:pihole-FTL'))

    def test_missing_admin_hash_keeps_adguard_in_setup_state(self):
        result = self.shell(r'''
source <(sed -n '/^detect_adguard()/,/^}/p' nexo-dns.sh)
sed -i '/^  password:/d' "$AGH_YAML"
detect_adguard
[[ "$AGH_READY" == 0 ]]
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
