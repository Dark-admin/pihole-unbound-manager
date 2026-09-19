import os
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "nexo-dns.sh"


class TuiBrandTests(unittest.TestCase):
    def banner(self, engine, layout):
        env = os.environ.copy()
        env.update({
            "NO_COLOR": "1",
            "TERM": "xterm",
            "NEXO_ENGINE": engine,
            "NEXO_LOGO": layout,
            "LC_ALL": "C.UTF-8",
        })
        return subprocess.run(
            ["bash", str(SCRIPT), "banner"],
            cwd=str(ROOT), env=env, capture_output=True, text=True,
            timeout=10, check=False,
        )

    def assert_box_is_aligned(self, output):
        rows = [line for line in output.splitlines()
                if len(line) >= 3 and line[2] in "╭│╰"]
        self.assertGreater(len(rows), 4)
        self.assertEqual(1, len({len(line) for line in rows}), output)

    def test_pihole_and_adguard_have_distinct_branding(self):
        pihole = self.banner("pihole", "mini")
        adguard = self.banner("adguard", "mini")
        self.assertEqual(0, pihole.returncode, pihole.stderr)
        self.assertEqual(0, adguard.returncode, adguard.stderr)
        self.assertIn("Pi-hole • Unbound • Tailscale", pihole.stdout)
        self.assertIn("AdGuard Home • Unbound • Tailscale", adguard.stdout)
        self.assertNotEqual(pihole.stdout, adguard.stdout)
        self.assert_box_is_aligned(pihole.stdout)
        self.assert_box_is_aligned(adguard.stdout)

    def test_all_layouts_keep_the_frame_aligned(self):
        for layout in ("grande", "mini", "no"):
            with self.subTest(layout=layout):
                result = self.banner("adguard", layout)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn("nexo-dns v4.3", result.stdout)
                self.assert_box_is_aligned(result.stdout)

    def test_invalid_engine_override_is_rejected(self):
        result = self.banner("otro", "mini")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("NEXO_ENGINE debe ser pihole o adguard", result.stdout)

    def test_responsive_breakpoints_protect_menu_columns(self):
        shell = r"""
source <(sed '/^COMMAND=/,$d' nexo-dns.sh)
term_dim() {
  if [[ "$1" == cols ]]; then printf '%s' "$TEST_COLS";
  else printf '%s' "$TEST_LINES"; fi
}
elegir_layout
printf '%s|%s|%s\n' "$BOXW" "$MENU_COLS" "$LAYOUT"
"""
        cases = (
            (39, 60, "33|1|texto"),
            (40, 60, "34|1|mini"),
            (67, 60, "61|1|mini"),
            (68, 60, "62|2|grande"),
        )
        for cols, lines, expected in cases:
            with self.subTest(cols=cols, lines=lines):
                env = os.environ.copy()
                env.update({"NO_COLOR": "1", "TERM": "xterm",
                            "TEST_COLS": str(cols), "TEST_LINES": str(lines)})
                result = subprocess.run(
                    ["bash", "-c", shell], cwd=str(ROOT), env=env,
                    capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(expected, result.stdout.strip())

    def test_remote_installers_are_never_piped_to_a_shell(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIsNone(
            re.search(r"^[^#\n]*\bcurl\b[^\n]*\|\s*(?:ba)?sh\b", source, re.M),
            "Descarga el instalador a un temporal, valídalo y luego ejecútalo",
        )


if __name__ == "__main__":
    unittest.main()
