import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("corruption_pack", Path(__file__).parents[1] / "corruption-pack.py")
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)


class CorruptionPackTests(unittest.TestCase):
    def test_private_pack_manifest_and_explicit_database_exclusion(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            report = root / "forensics.json"
            report.write_text('{"format_version":1}')
            output = root / "pack.tar.gz"
            args = pack.parser().parse_args(["--output", str(output), "--forensic-record", str(report),
                                            "--wn-agent", "/missing/wn-agent"])
            pack.pack(args)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with tarfile.open(output) as archive:
                manifest = json.load(archive.extractfile("manifest.json"))
                self.assertFalse(manifest["contains_database"])
                self.assertFalse(manifest["coverage"]["integrity"])
                self.assertEqual(manifest["artifacts"][0]["bytes"], report.stat().st_size)
                self.assertTrue(all(m.mode == 0o600 for m in archive))
            with self.assertRaises(FileExistsError):
                pack.pack(args)

    def test_symlink_and_nonregular_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            target = root / "target"
            target.write_text("secret")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                pack.read_regular(link, 100)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                pack.read_regular(fifo, 100)
            with self.assertRaises(ValueError):
                pack.read_regular(target, 2)

    def test_subprocess_limits_output_and_time(self):
        data, status = pack.run_bounded([sys.executable, "-c", "print('x'*10000)"], limit=100)
        self.assertEqual(len(data), 100)
        self.assertEqual(status["incomplete_reason"], "byte_limit")
        _, status = pack.run_bounded([sys.executable, "-c", "import time; time.sleep(10)"], timeout=.05)
        self.assertEqual(status["incomplete_reason"], "timeout")

    def test_failed_input_does_not_leave_misleading_archive(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "pack.tar.gz"
            args = pack.parser().parse_args(["--output", str(output), "--forensic-record", str(output.parent / "missing")])
            with self.assertRaises(OSError):
                pack.pack(args)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
