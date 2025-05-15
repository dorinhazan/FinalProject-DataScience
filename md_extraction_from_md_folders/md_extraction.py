from pathlib import Path
import shutil

source_root = Path("/Users/nettayaakobi/Desktop/ICS_REPORTS/ICS_MARKDOWNs_73")
destination_dir = Path("/Users/nettayaakobi/Desktop/validation_73")
destination_dir.mkdir(exist_ok=True)

for subfolder in source_root.iterdir():
    if subfolder.is_dir():
        md_files = list(subfolder.glob("*.md"))
        if not md_files:
            print(f"No .md files in {subfolder.name}")
        for md_file in md_files:
            dest_file = destination_dir / md_file.name
            counter = 1
            while dest_file.exists():
                dest_file = destination_dir / f"{md_file.stem}_{counter}{md_file.suffix}"
                counter += 1
            shutil.copy(md_file, dest_file)
            print(f"Copied: {md_file} -> {dest_file}")
