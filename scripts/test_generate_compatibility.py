import tempfile
import unittest
from pathlib import Path

from scripts.generate_compatibility import (
    REQUIRED_FIELDS,
    collect_tutorials,
    parse_config,
    render,
    validate_metadata,
)


class CompatibilityMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).resolve().parent.parent
        cls.tutorials = collect_tutorials(cls.project_root / "src")

    def test_every_tutorial_has_valid_metadata(self):
        config_paths = list((self.project_root / "src").rglob(".config"))
        self.assertTrue(config_paths)
        self.assertEqual(len(config_paths), len(self.tutorials))
        for path in config_paths:
            metadata = parse_config(path)
            self.assertTrue(set(REQUIRED_FIELDS) <= set(metadata), path)

    def test_bilingual_tables_contain_every_tutorial(self):
        for chinese in (False, True):
            table = render(self.tutorials, chinese=chinese)
            self.assertEqual(len(self.tutorials), table.count("| ["))
            for tutorial in self.tutorials:
                readme = "README.zh.md" if chinese else "README.md"
                expected = f"{tutorial['relative'].as_posix()}/{readme}"
                self.assertIn(expected, table)

    def test_missing_field_is_rejected(self):
        metadata = {
            "kernel_min": "5.15",
            "kernel_min_basis": "required-feature",
            "architectures": "x86_64",
            "btf": "optional",
            "kernel_config": "CONFIG_BPF=y",
            "hardware": "none",
            "root": "required",
        }
        with self.assertRaisesRegex(ValueError, "test_status"):
            validate_metadata(Path("example/.config"), metadata)

    def test_required_btf_config_is_enforced(self):
        metadata = {
            "kernel_min": "5.15",
            "kernel_min_basis": "required-feature",
            "architectures": "x86_64",
            "btf": "required",
            "kernel_config": "CONFIG_BPF=y",
            "hardware": "none",
            "root": "required",
            "test_status": "not-in-ci",
        }
        with self.assertRaisesRegex(ValueError, "CONFIG_DEBUG_INFO_BTF"):
            validate_metadata(Path("example/.config"), metadata)

    def test_duplicate_config_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".config"
            path.write_text("level=Basic\nlevel=Depth\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate field level"):
                parse_config(path)

    def test_empty_csv_item_is_rejected(self):
        metadata = {
            "kernel_min": "5.15",
            "kernel_min_basis": "repository-baseline",
            "architectures": "x86_64,,arm64",
            "btf": "optional",
            "kernel_config": "CONFIG_BPF=y",
            "hardware": "none",
            "root": "required",
            "test_status": "not-in-ci",
        }
        with self.assertRaisesRegex(ValueError, "architectures"):
            validate_metadata(Path("example/.config"), metadata)

    def test_per_arch_kernel_min_covers_all_architectures(self):
        metadata = {
            "kernel_min": "x86_64:5.5",
            "kernel_min_basis": "documented",
            "architectures": "x86_64,arm64",
            "btf": "optional",
            "kernel_config": "CONFIG_BPF=y",
            "hardware": "none",
            "root": "required",
            "test_status": "not-in-ci",
        }
        with self.assertRaisesRegex(ValueError, "kernel_min"):
            validate_metadata(Path("example/.config"), metadata)

    def test_not_applicable_basis_requires_not_applicable_kernel(self):
        metadata = {
            "kernel_min": "5.15",
            "kernel_min_basis": "not-applicable",
            "architectures": "x86_64",
            "btf": "optional",
            "kernel_config": "CONFIG_BPF=y",
            "hardware": "none",
            "root": "required",
            "test_status": "not-in-ci",
        }
        with self.assertRaisesRegex(ValueError, "disagree"):
            validate_metadata(Path("example/.config"), metadata)

    def test_repository_baseline_is_consistent(self):
        metadata = {
            "kernel_min": "5.15",
            "kernel_min_basis": "repository-baseline",
            "architectures": "x86_64",
            "btf": "optional",
            "kernel_config": "CONFIG_BPF=y,CONFIG_BPF_SYSCALL=y",
            "hardware": "none",
            "root": "required",
            "test_status": "not-in-ci",
        }
        with self.assertRaisesRegex(ValueError, "repository-baseline must be 4.8"):
            validate_metadata(Path("example/.config"), metadata)


if __name__ == "__main__":
    unittest.main()
