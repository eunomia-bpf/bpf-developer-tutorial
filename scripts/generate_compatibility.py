#!/usr/bin/env python3
"""Validate tutorial compatibility metadata and generate compatibility tables."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


REQUIRED_FIELDS = (
    "kernel_min",
    "kernel_min_basis",
    "architectures",
    "btf",
    "kernel_config",
    "hardware",
    "root",
    "test_status",
)
ARCHITECTURES = {"all", "x86_64", "arm64"}
BTF_VALUES = {"required", "optional", "not-required"}
ROOT_VALUES = {"required", "not-required"}
TEST_STATUSES = {"ci-runtime", "ci-build", "not-in-ci", "docs-only"}
KERNEL_BASES = {
    "documented",
    "required-feature",
    "repository-baseline",
    "unverified",
    "not-applicable",
}
HARDWARE_VALUES = {
    "none",
    "android-device-or-emulator",
    "block-device",
    "drm-gpu",
    "gpu",
    "intel-npu",
    "network-interface",
    "nvidia-cuda-gpu",
}
KERNEL_VERSION = re.compile(r"^\d+\.\d+$")
ARCH_KERNEL_VERSION = re.compile(r"^(x86_64|arm64):\d+\.\d+$")
KERNEL_CONFIG = re.compile(r"^CONFIG_[A-Z0-9_]+=(?:y|m|y\|m)$")
REPOSITORY_BASELINE = "4.8"


def sort_key(path: Path) -> tuple:
    """Match the natural ordering used by the tutorial indexes."""
    relative = path.parent.as_posix()
    numbers = tuple(map(int, re.findall(r"\d+", relative)))
    return (0, numbers, relative) if numbers else (1, (), relative)


def parse_config(path: Path) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path}:{line_number}: expected key=value")
        key, value = line.split("=", 1)
        if key in metadata:
            raise ValueError(f"{path}:{line_number}: duplicate field {key}")
        metadata[key] = value
    return metadata


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",")]


def validate_metadata(path: Path, metadata: dict[str, str]) -> None:
    missing = [field for field in REQUIRED_FIELDS if not metadata.get(field)]
    if missing:
        raise ValueError(f"{path}: missing required fields: {', '.join(missing)}")

    architectures = _csv(metadata["architectures"])
    if (
        not architectures
        or len(architectures) != len(set(architectures))
        or not set(architectures) <= ARCHITECTURES
        or ("all" in architectures and len(architectures) != 1)
    ):
        raise ValueError(f"{path}: invalid architectures={metadata['architectures']}")

    kernel_min = metadata["kernel_min"]
    if kernel_min not in {"not-applicable", "unknown"} and not KERNEL_VERSION.fullmatch(kernel_min):
        per_arch = _csv(kernel_min)
        per_arch_names = [item.split(":", 1)[0] for item in per_arch]
        if (
            not per_arch
            or not all(ARCH_KERNEL_VERSION.fullmatch(item) for item in per_arch)
            or len(per_arch_names) != len(set(per_arch_names))
            or set(per_arch_names) != set(architectures)
        ):
            raise ValueError(f"{path}: invalid kernel_min={kernel_min}")
    if metadata["kernel_min_basis"] not in KERNEL_BASES:
        raise ValueError(f"{path}: invalid kernel_min_basis={metadata['kernel_min_basis']}")
    if (kernel_min == "not-applicable") != (
        metadata["kernel_min_basis"] == "not-applicable"
    ):
        raise ValueError(f"{path}: kernel_min and kernel_min_basis disagree")
    if (kernel_min == "unknown") != (metadata["kernel_min_basis"] == "unverified"):
        raise ValueError(f"{path}: unknown kernel_min must use an unverified basis")
    if (
        metadata["kernel_min_basis"] == "repository-baseline"
        and kernel_min != REPOSITORY_BASELINE
    ):
        raise ValueError(
            f"{path}: repository-baseline must be {REPOSITORY_BASELINE}, got {kernel_min}"
        )

    if metadata["btf"] not in BTF_VALUES:
        raise ValueError(f"{path}: invalid btf={metadata['btf']}")
    if metadata["root"] not in ROOT_VALUES:
        raise ValueError(f"{path}: invalid root={metadata['root']}")
    if metadata["test_status"] not in TEST_STATUSES:
        raise ValueError(f"{path}: invalid test_status={metadata['test_status']}")
    if metadata["hardware"] not in HARDWARE_VALUES:
        raise ValueError(f"{path}: invalid hardware={metadata['hardware']}")

    configs = _csv(metadata["kernel_config"])
    if metadata["kernel_config"] != "none" and (
        not configs
        or len(configs) != len(set(configs))
        or not all(KERNEL_CONFIG.fullmatch(item) for item in configs)
    ):
        raise ValueError(f"{path}: invalid kernel_config={metadata['kernel_config']}")
    if metadata["btf"] == "required" and "CONFIG_DEBUG_INFO_BTF=y" not in configs:
        raise ValueError(f"{path}: btf=required needs CONFIG_DEBUG_INFO_BTF=y")
    if kernel_min != "not-applicable" and not {
        "CONFIG_BPF=y",
        "CONFIG_BPF_SYSCALL=y",
    } <= set(configs):
        raise ValueError(f"{path}: runnable tutorials need CONFIG_BPF=y and CONFIG_BPF_SYSCALL=y")
    if (kernel_min == "not-applicable") != (metadata["test_status"] == "docs-only"):
        raise ValueError(f"{path}: docs-only status and not-applicable kernel must agree")

    if kernel_min == "not-applicable" and (
        metadata["kernel_min_basis"] != "not-applicable"
        or
        metadata["architectures"] != "all"
        or metadata["btf"] != "not-required"
        or metadata["kernel_config"] != "none"
        or metadata["hardware"] != "none"
        or metadata["root"] != "not-required"
        or metadata["test_status"] != "docs-only"
    ):
        raise ValueError(f"{path}: not-applicable tutorials must use docs-only defaults")


def _title(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            return line.lstrip("#").strip()
    raise ValueError(f"{path}: missing Markdown title")


def collect_tutorials(src_dir: Path) -> list[dict[str, object]]:
    tutorials = []
    for config_path in sorted(
        src_dir.rglob(".config"), key=lambda path: sort_key(path.relative_to(src_dir))
    ):
        metadata = parse_config(config_path)
        validate_metadata(config_path, metadata)
        lesson_dir = config_path.parent
        english = lesson_dir / "README.md"
        chinese = lesson_dir / "README.zh.md"
        if not english.exists() or not chinese.exists():
            raise ValueError(f"{lesson_dir}: both English and Chinese READMEs are required")
        tutorials.append(
            {
                "relative": lesson_dir.relative_to(src_dir),
                "title_en": _title(english),
                "title_zh": _title(chinese),
                "metadata": metadata,
            }
        )
    return tutorials


DISPLAY = {
    "required": "Required",
    "optional": "Optional",
    "not-required": "Not required",
    "not-applicable": "N/A",
    "ci-runtime": "CI runtime",
    "ci-build": "CI build",
    "not-in-ci": "Not in CI",
    "docs-only": "Docs only",
    "none": "None",
    "all": "All",
    "documented": "Tutorial docs",
    "required-feature": "Required feature",
    "repository-baseline": "Repository baseline",
    "unverified": "Unverified",
    "unknown": "Unknown",
    "android-device-or-emulator": "Android device or emulator",
    "block-device": "Block device",
    "drm-gpu": "DRM GPU",
    "gpu": "GPU",
    "intel-npu": "Intel NPU",
    "network-interface": "Network interface",
    "nvidia-cuda-gpu": "NVIDIA CUDA GPU",
}
DISPLAY_ZH = {
    "required": "需要",
    "optional": "可选",
    "not-required": "不需要",
    "not-applicable": "不适用",
    "ci-runtime": "CI 运行测试",
    "ci-build": "CI 构建测试",
    "not-in-ci": "未纳入 CI",
    "docs-only": "仅文档",
    "none": "无",
    "all": "全部",
    "documented": "教程文档",
    "required-feature": "必需特性",
    "repository-baseline": "仓库基线",
    "unverified": "尚未验证",
    "unknown": "未知",
    "android-device-or-emulator": "Android 设备或模拟器",
    "block-device": "块设备",
    "drm-gpu": "DRM GPU",
    "gpu": "GPU",
    "intel-npu": "Intel NPU",
    "network-interface": "网络接口",
    "nvidia-cuda-gpu": "NVIDIA CUDA GPU",
}


def _display(value: str, chinese: bool = False) -> str:
    mapping = DISPLAY_ZH if chinese else DISPLAY
    if "," in value:
        return ", ".join(_display(item, chinese) for item in _csv(value))
    return mapping.get(value, value.replace("-", " "))


def render(tutorials: list[dict[str, object]], chinese: bool = False) -> str:
    if chinese:
        lines = [
            "# 教程兼容性矩阵",
            "",
            "<!-- Generated by scripts/generate_compatibility.py; do not edit directly. -->",
            "",
            "本表由各教程的 `.config` 元数据生成。`最低内核` 表示教程按当前写法声明支持的最低版本；`依据` 标明该值来自教程文档、必需特性首次出现的版本，还是仓库声明的基线。`未纳入 CI` 不表示已做过手工验证。内核发行版可能禁用所列配置，因此版本号本身并不能保证兼容。",
            "",
            "| 教程 | 最低内核 | 依据 | 架构 | BTF | 核心内核配置 | 硬件 | Root | 测试状态 |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    else:
        lines = [
            "# Tutorial compatibility matrix",
            "",
            "<!-- Generated by scripts/generate_compatibility.py; do not edit directly. -->",
            "",
            "This table is generated from each tutorial's `.config` metadata. `Minimum kernel` means the oldest kernel that the tutorial currently declares support for. `Basis` says whether that value comes from the tutorial documentation, the first version of a required feature, or the repository's declared baseline. `Not in CI` does not imply that a manual test was performed. Distribution kernels may disable a listed option, so a version number alone does not guarantee compatibility.",
            "",
            "| Tutorial | Minimum kernel | Basis | Architectures | BTF | Core kernel config | Hardware | Root | Test status |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]

    for tutorial in tutorials:
        relative = tutorial["relative"]
        metadata = tutorial["metadata"]
        assert isinstance(relative, Path)
        assert isinstance(metadata, dict)
        readme = "README.zh.md" if chinese else "README.md"
        title_key = "title_zh" if chinese else "title_en"
        title = str(tutorial[title_key]).replace("|", "\\|")
        link = f"{relative.as_posix()}/{readme}"
        values = [
            metadata["kernel_min"],
            metadata["kernel_min_basis"],
            metadata["architectures"],
            metadata["btf"],
            metadata["kernel_config"],
            metadata["hardware"],
            metadata["root"],
            metadata["test_status"],
        ]
        displayed = [_display(value, chinese).replace("|", "\\|") for value in values]
        lines.append(f"| [{title}]({link}) | {' | '.join(displayed)} |")

    lines.extend(["", "## Metadata fields" if not chinese else "## 元数据字段", ""])
    if chinese:
        lines.extend(
            [
                "- `kernel_min` 与 `kernel_min_basis`：教程声明的最低内核及其依据；按架构不同时使用 `架构:版本`。",
                "- `architectures`：教程当前声明支持的架构。",
                "- `btf` 与 `kernel_config`：BTF 要求以及各实现路径共有的核心内核选项；供应商或挂载点特有的条件请参阅对应教程。`y|m` 表示内建或模块均可。",
                "- `hardware`：运行教程所需的专用硬件或环境；`none` 表示不需要专用硬件。",
                "- `root`：运行教程是否需要 root 权限。",
                "- `test_status`：`ci-runtime` 会在 CI 中实际运行，`ci-build` 仅验证构建，`not-in-ci` 表示没有 CI 证据，`docs-only` 表示纯文档。",
                "",
                "字段定义和允许值由 `scripts/generate_compatibility.py` 校验；修改教程要求时，请更新对应 `.config` 并重新运行生成脚本。",
            ]
        )
    else:
        lines.extend(
            [
                "- `kernel_min` and `kernel_min_basis`: the declared minimum kernel and its evidence basis; use `architecture:version` when architectures differ.",
                "- `architectures`: architectures the tutorial currently declares support for.",
                "- `btf` and `kernel_config`: the BTF requirement and core kernel options common to the implementation paths; see the tutorial for vendor- or hook-specific conditions. `y|m` means built in or loaded as a module.",
                "- `hardware`: specialized hardware or environment required to run the tutorial; `none` means no specialized hardware.",
                "- `root`: whether running the tutorial requires root privileges.",
                "- `test_status`: `ci-runtime` executes in CI, `ci-build` checks only the build, `not-in-ci` means there is no CI evidence, and `docs-only` is documentation only.",
                "",
                "Field definitions and allowed values are validated by `scripts/generate_compatibility.py`. When a tutorial requirement changes, update its `.config` and rerun the generator.",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def generate(project_root: Path, check: bool = False) -> None:
    tutorials = collect_tutorials(project_root / "src")
    outputs = {
        project_root / "src" / "compatibility.md": render(tutorials),
        project_root / "src" / "compatibility.zh.md": render(tutorials, chinese=True),
    }
    stale = []
    for path, content in outputs.items():
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(path)
        else:
            path.write_text(content, encoding="utf-8")
            print(f"Generated: {path}")
    if stale:
        names = ", ".join(str(path.relative_to(project_root)) for path in stale)
        raise SystemExit(f"Generated compatibility documentation is stale: {names}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="validate without rewriting files")
    args = parser.parse_args()
    generate(Path(__file__).resolve().parent.parent, check=args.check)


if __name__ == "__main__":
    main()
