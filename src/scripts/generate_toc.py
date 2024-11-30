import os
import re

# Define a function to walk through the directory and generate the TOC structure
def generate_toc(base_dir, project_root):
    toc = "## Table of Contents\n\n"
    section_headers = {
        "Basic": "### Getting Started Examples\n\nThis section contains simple eBPF program examples and introductions. It primarily utilizes the `eunomia-bpf` framework to simplify development and introduces the basic usage and development process of eBPF.\n\n",
        "Advance": "### Advanced Documents and Examples\n\nWe start to build complete eBPF projects mainly based on `libbpf` and combine them with various application scenarios for practical use.\n\n",
        "Depth": "### In-Depth Topics\n\nThis section covers advanced topics related to eBPF, including using eBPF programs on Android, possible attacks and defenses using eBPF programs, and complex tracing. Combining the user-mode and kernel-mode aspects of eBPF can bring great power (as well as security risks).\n\n"
    }

    subsection_titles = {
        "Android": "\n\nAndroid:\n\n",
        "Networking": "\n\nNetworking:\n\n",
        "tracing": "\n\ntracing:\n\n",
        "Security": "\n\nSecurity:\n\n",
        "Scheduler": "\n\nScheduler:\n\n",
        "Other": "\n\nOther:\n\n"
    }

    subsection_order = ['Android', 'Networking', 'tracing', 'Security', 'Scheduler', 'Other']

    # To ensure numeric sorting of directories
    def sort_key(directory_name):
        return list(map(int, re.findall(r'\d+', directory_name)))

    sections = {}  # {section_level: {subsection_type: [lessons]}}

    # Sort directories properly by numeric order
    all_dirs = sorted([d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))], key=sort_key)

    # Loop over the sorted directories
    for directory in all_dirs:
        lesson_path = os.path.join(base_dir, directory)
        config_path = os.path.join(lesson_path, ".config")
        readme_path = os.path.join(lesson_path, "README.md")

        if os.path.exists(config_path) and os.path.exists(readme_path):
            # Read the .config file for 'level', 'type', and 'desc'
            with open(config_path, 'r') as config_file:
                config_lines = config_file.readlines()
                level = None
                lesson_type = None
                desc = None
                for line in config_lines:
                    if line.startswith("level="):
                        level = line.split("=",1)[1].strip()
                    elif line.startswith("type="):
                        lesson_type = line.split("=",1)[1].strip()
                    elif line.startswith("desc="):
                        desc = line.split("=",1)[1].strip()

            # Extract the first markdown title in README_en.md
            with open(readme_path, 'r') as readme_file:
                first_title = None
                for line in readme_file:
                    if line.startswith("#"):
                        first_title = line.strip().lstrip("#").strip()
                        break

            # If title starts with "eBPF", remove the part before the colon
            if first_title and first_title.startswith("eBPF"):
                if ":" in first_title:
                    first_title = first_title.split(":", 1)[1].strip()

            # Get the relative path for the lesson
            lesson_rel_path = os.path.relpath(readme_path, project_root)

            # Prepare lesson data
            lesson_number = directory.split('-')[0]
            lesson_name = directory.split('-', 1)[1]
            link_text = f"lesson {lesson_number}-{lesson_name}"
            link = f"{lesson_rel_path}"
            # Use description if available, else use first title
            lesson_desc = desc if desc else first_title

            lesson_entry = {
                'link_text': link_text,
                'link': link,
                'desc': lesson_desc
            }

            # Organize lessons into sections and subsections
            sections.setdefault(level, {}).setdefault(lesson_type, []).append(lesson_entry)

    # Now, output the TOC in the desired order
    section_order = ['Basic', 'Advance', 'Depth']

    for level in section_order:
        if level in sections:
            toc += section_headers.get(level, "")
            # For Basic and Advance sections, no subsections
            if level != 'Depth':
                for lesson in sum(sections[level].values(), []):  # Flatten the list
                    toc += f"- [{lesson['link_text']}]({lesson['link']}) {lesson['desc']}\n"
            else:
                # For Depth section, output subsections in the desired order
                for subsection in subsection_order:
                    if subsection in sections[level]:
                        toc += subsection_titles.get(subsection, "")
                        for lesson in sections[level][subsection]:
                            toc += f"- [{lesson['link_text']}]({lesson['link']}) {lesson['desc']}\n"

    toc += "\nContinuously updating..."
    return toc


# Define a function to walk through the directory and generate the TOC structure in Chinese
def generate_toc_cn(base_dir, project_root):
    toc = "## 目录\n\n"
    section_headers = {
        "Basic": "### 入门示例\n\n这一部分包含简单的 eBPF 程序示例和介绍。主要利用 `eunomia-bpf` 框架简化开发，介绍 eBPF 的基本用法和开发流程。\n\n",
        "Advance": "### 高级文档和示例\n\n我们开始构建完整的 eBPF 项目，主要基于 `libbpf`，并将其与各种应用场景结合起来，以便实际使用。\n\n",
        "Depth": "### 深入主题\n\n这一部分涵盖了与 eBPF 相关的高级主题，包括在 Android 上使用 eBPF 程序、利用 eBPF 程序进行的潜在攻击和防御以及复杂的追踪。结合用户模式和内核模式的 eBPF 可以带来强大的能力（也可能带来安全风险）。\n\n"
    }

    subsection_titles = {
        "Android": "Android:\n\n",
        "Networking": "网络:\n\n",
        "tracing": "追踪:\n\n",
        "Security": "安全:\n\n",
        "Scheduler": "调度器:\n\n",
        "Other": "其他:\n\n"
    }

    subsection_order = ['Android', 'Networking', 'tracing', 'Security', 'Scheduler', 'Other']

    # To ensure numeric sorting of directories
    def sort_key(directory_name):
        return list(map(int, re.findall(r'\d+', directory_name)))

    sections = {}  # {section_level: {subsection_type: [lessons]}}

    # Sort directories properly by numeric order
    all_dirs = sorted([d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))], key=sort_key)

    # Loop over the sorted directories
    for directory in all_dirs:
        lesson_path = os.path.join(base_dir, directory)
        config_path = os.path.join(lesson_path, ".config")
        readme_path = os.path.join(lesson_path, "README.zh.md")

        if os.path.exists(config_path) and os.path.exists(readme_path):
            # Read the .config file for 'level', 'type', and 'desc'
            with open(config_path, 'r') as config_file:
                config_lines = config_file.readlines()
                level = None
                lesson_type = None
                desc = None
                for line in config_lines:
                    if line.startswith("level="):
                        level = line.split("=",1)[1].strip()
                    elif line.startswith("type="):
                        lesson_type = line.split("=",1)[1].strip()
                    elif line.startswith("desc="):
                        desc = line.split("=",1)[1].strip()

            # Extract the first markdown title in README.md
            with open(readme_path, 'r') as readme_file:
                first_title = None
                for line in readme_file:
                    if line.startswith("#"):
                        first_title = line.strip().lstrip("#").strip()
                        break

            # If title starts with "eBPF", remove the part before the colon
            if first_title and first_title.startswith("eBPF"):
                if ":" in first_title:
                    first_title = first_title.split(":", 1)[1].strip()

            # Get the relative path for the lesson
            lesson_rel_path = os.path.relpath(readme_path, project_root)

            # Prepare lesson data
            lesson_number = directory.split('-')[0]
            lesson_name = directory.split('-', 1)[1]
            link_text = f"lesson {lesson_number}-{lesson_name}"
            link = f"{lesson_rel_path}"
            # Use description if available, else use first title
            lesson_desc = desc if desc else first_title

            lesson_entry = {
                'link_text': link_text,
                'link': link,
                'desc': lesson_desc
            }

            # Organize lessons into sections and subsections
            sections.setdefault(level, {}).setdefault(lesson_type, []).append(lesson_entry)

    # Now, output the TOC in the desired order
    section_order = ['Basic', 'Advance', 'Depth']

    for level in section_order:
        if level in sections:
            toc += section_headers.get(level, "")
            # For Basic and Advance sections, no subsections
            if level != 'Depth':
                for lesson in sum(sections[level].values(), []):  # Flatten the list
                    toc += f"- [{lesson['link_text']}]({lesson['link']}) {lesson['desc']}\n"
            else:
                # For Depth section, output subsections in the desired order
                for subsection in subsection_order:
                    if subsection in sections[level]:
                        toc += subsection_titles.get(subsection, "")
                        for lesson in sections[level][subsection]:
                            toc += f"- [{lesson['link_text']}]({lesson['link']}) {lesson['desc']}\n"

    toc += "\n持续更新中..."
    return toc

# Example usage
base_directory = "src/"  # Replace with the actual base directory
project_root = "./"  # The root of the project
toc_output = generate_toc(base_directory, project_root)
# toc_output = generate_toc_cn(base_directory, project_root)
# Output the TOC
print(toc_output)
