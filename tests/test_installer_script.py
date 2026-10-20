import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEBOS26 = ROOT / "wwwroot" / "autoroot-webos26.sh"
COMPAT = ROOT / "wwwroot" / "autoroot.sh"
PINNED_SHA256 = "d10bf3c753551d7c72fb7a92b20fcd2317e502a220ac668ba8e76f6ea78b363c"


class InstallerScriptTest(unittest.TestCase):
    def test_legacy_and_webos26_scripts_are_identical(self):
        self.assertEqual(WEBOS26.read_bytes(), COMPAT.read_bytes())

    def test_ipk_hash_is_pinned(self):
        source = WEBOS26.read_text(encoding="utf-8")
        self.assertIn("IPK_SHA256='%s'" % PINNED_SHA256, source)
        self.assertIn("verify_ipk \"${ipk}\"", source)

    def test_installer_has_emergency_backup(self):
        source = WEBOS26.read_text(encoding="utf-8")
        self.assertIn("create_backup_dir", source)
        self.assertIn(
            "backup_path '/var/luna/preferences/devmode_enabled'", source
        )
        self.assertIn('backup_path "${sd_script}"', source)
        self.assertIn('backup_path "${sd_sig}"', source)

    def test_installer_retries_only_once(self):
        source = WEBOS26.read_text(encoding="utf-8")
        self.assertIn("max_attempts=2", source)
        self.assertNotIn("retries=3", source)
        self.assertNotIn("seq \"${retries}\"", source)

    def test_installer_disables_normal_hbc_telnet(self):
        source = WEBOS26.read_text(encoding="utf-8")
        self.assertIn("webosbrew_telnet_disabled", source)
        self.assertIn("failsafe", source)

    def test_download_uses_tls_and_fail(self):
        source = WEBOS26.read_text(encoding="utf-8")
        self.assertIn("--fail --proto '=https'", source)

    def test_hash_constant_is_sha256(self):
        self.assertRegex(PINNED_SHA256, r"^[0-9a-f]{64}$")
        self.assertIsNotNone(re.fullmatch(r"[0-9a-f]{64}", PINNED_SHA256))


if __name__ == "__main__":
    unittest.main()
