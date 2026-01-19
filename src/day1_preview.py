import os
from pathlib import Path

DATA_DIR = Path("data")

SKIP_FILES = {"anomaly_labels.txt", "abnormal_label.txt", "normal_label.txt"}

def list_log_files(root: Path, max_files=20):
    files = []
    for path in root.rglob("*"):
        if path.is_file():
            name = path.name.lower()
            if name in SKIP_FILES:
                continue
            if name.endswith(".log") or name.endswith(".txt"):
                files.append(path)
    return files[:max_files], len(files)

def read_first_lines(file_path: Path, n=10):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = []
            for _ in range(n):
                line = f.readline()
                if not line:
                    break
                lines.append(line.rstrip("\n"))
            return lines
    except Exception as e:
        return [f"❌ Error reading file: {e}"]

def main():
    if not DATA_DIR.exists():
        print("❌ data/ folder not found.")
        return

    print("✅ Kaggle dataset folders found:\n")
    for item in sorted(DATA_DIR.iterdir()):
        if item.is_dir():
            print(" -", item.name)

    print("\n✅ Scanning for log files...")
    sample_files, total_files = list_log_files(DATA_DIR)

    print(f"✅ Total log/text files found (excluding label files): {total_files}")
    print("\n✅ Sample files:")
    for f in sample_files:
        print(" -", f)

    if sample_files:
        first_file = sample_files[0]
        print("\n📌 Showing first 10 lines of:", first_file)
        lines = read_first_lines(first_file, n=10)
        for line in lines:
            print(line)

if __name__ == "__main__":
    main()
