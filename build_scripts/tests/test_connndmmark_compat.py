"""Actual adapter code, compiled against xtables headers; not a kernel emulator."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
INCLUDE = Path(os.environ.get('KEEN_PBR_XTABLES_INCLUDE', '/usr/include'))


@unittest.skipUnless(shutil.which('gcc') and (INCLUDE / 'xtables.h').is_file(),
                     'xtables development headers required (use Entware SDK include path)')
class ConnndmmarkAdapterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='kpbr-ndm-abi-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.binary = Path(cls.tmp.name) / 'compat-test'
        subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-I' + str(INCLUDE), str(ROOT / 'build_scripts/tests/connndmmark_compat_test.c'),
                        '-Wl,--wrap=socket,--wrap=getsockopt,--wrap=close,--wrap=dlsym',
                        '-o', str(cls.binary)], check=True, capture_output=True, text=True)

    def test_actual_c_callbacks_keep_revision_one_bytes_and_defer_to_new_entware(self):
        result = subprocess.run([str(self.binary)], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.splitlines()[:3],
                         [' ! --mark 0x20/0x20', ' --mark 0x12340000/0xffff0000',
                          ' ! --mark 0x0/0xffffffff'])
        self.assertIn('native-update deferral: PASS', result.stdout)

    def test_never_interprets_short_or_different_revision_data_as_revision_one(self):
        for invalid in ('bad-size', 'bad-revision'):
            with self.subTest(invalid=invalid):
                result = subprocess.run([str(self.binary), invalid], capture_output=True)
                self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
