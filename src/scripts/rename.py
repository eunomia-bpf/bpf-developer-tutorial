import os

def rename_readme_files(base_dir):
    # Walk through all directories and files starting from base_dir
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            file_path = os.path.join(root, file)

            # Rename README.md to README.zh.md if README.md exists after the previous rename
            if file == "README.md":
                zh_file_path = os.path.join(root, "README.zh.md")
                os.rename(file_path, zh_file_path)
                print(f"Renamed {file_path} to {zh_file_path}")

            # Rename README_en.md to README.md
            elif file == "README_en.md":
                new_file_path = os.path.join(root, "README.md")
                os.rename(file_path, new_file_path)
                print(f"Renamed {file_path} to {new_file_path}")

# Example usage
base_directory = "/root/bpf-developer-tutorial/src"  # Replace with the actual base directory
rename_readme_files(base_directory)
