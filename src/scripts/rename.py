import os

def rename_readme_en_to_readme(base_dir):
    # First pass: Rename README_en.md to README.md
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            file_path = os.path.join(root, file)

            # Rename README_en.md to README.md
            if file == "README_en.md":
                new_file_path = os.path.join(root, "README.md")
                os.rename(file_path, new_file_path)
                print(f"Renamed {file_path} to {new_file_path}")

def rename_readme_to_readme_zh(base_dir):
    # Second pass: Rename README.md to README.zh.md
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            file_path = os.path.join(root, file)

            # Rename README.md to README.zh.md if it exists
            if file == "README.md":
                zh_file_path = os.path.join(root, "README.zh.md")
                os.rename(file_path, zh_file_path)
                print(f"Renamed {file_path} to {zh_file_path}")

# Example usage
base_directory = "/root/bpf-developer-tutorial/src"  # Replace with the actual base directory

# Second pass: Rename README.md to README.zh.md
rename_readme_to_readme_zh(base_directory)

# First pass: Rename README_en.md to README.md
rename_readme_en_to_readme(base_directory)
