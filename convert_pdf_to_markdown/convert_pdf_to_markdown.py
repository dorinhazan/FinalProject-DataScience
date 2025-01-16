import logging
import os
import subprocess
import argparse
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def process_pdfs(input_folder, output_folder, workers=4):
    """
    Process all PDFs in the input folder using the `marker` CLI and save the output in the output folder.
    Args:
        input_folder (str): Path to the folder containing PDF files.
        output_folder (str): Path to the folder where processed Markdown files will be saved.
        workers (int): Number of parallel workers for processing (default is 4).
    """
    if not os.path.exists(input_folder):
        print(f"Error: Input folder '{input_folder}' does not exist.")
        return

    os.makedirs(output_folder, exist_ok=True)

    command = [
        "marker",
        input_folder,
        "--output_format", "markdown",
        "--output_dir", output_folder,
        "--workers", str(workers),
        "--force_ocr"
    ]

    try:
        print(f"Running command: {' '.join(command)}")
        subprocess.run(command, check=True)
        print(f"Processing completed. Output saved to '{output_folder}'.")
    except subprocess.CalledProcessError as e:
        print(f"Error while executing the command: {e}")
    except FileNotFoundError:
        print("Error: `marker` CLI not found. Ensure the marker package is installed and accessible.")

def clean_markdown_files(output_folder):
    """
    Post-process all Markdown files in the output folder to remove unwanted content.
    Args:
        output_folder (str): Path to the folder containing processed Markdown files.
    """
    logging.info(f"Cleaning Markdown files in '{output_folder}'...")
    for root, _, files in os.walk(output_folder):  # os.walk for recursive traversal
        for file_name in files:
            if file_name.endswith(".md"):
                file_path = os.path.join(root, file_name)
                logging.info(f"Cleaning file: {file_path}")
                clean_markdown(file_path)

def clean_markdown(file_path):
    """
    Clean a single Markdown file by removing hyperlinks, annotations, headers, and footers.
    Args:
        file_path (str): Path to the Markdown file.
    """
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    logging.info(f"Cleaning file: {file_path}")

    # Patterns for removal
    patterns = {
        "inline_hyperlinks": r'\[.*?\]\(http[s]?://\S+?\)',  # Matches [text](http://example.com)
        "standalone_urls": r'http[s]?://\S+',  # Matches http://example.com
        # "annotations": r'\[\]\(\S+\)',  # Matches empty image annotations like []()
        "headers_footers": r'(Recommended Practice|Homeland Security|Page \d+)',  # Matches headers/footers
    }

    # Debugging: Print content before cleaning
    logging.debug(f"Original content:\n{content[:500]}")

    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            logging.info(f"Found {len(matches)} occurrences of {name}. Example: {matches[0]}")
        else:
            logging.info(f"Found {len(matches)} occurrences of {name}")
        content = re.sub(pattern, '', content)


    # Debugging: Print content after cleaning
    logging.debug(f"Cleaned content:\n{content[:500]}")

    # Save the cleaned content
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(content)

    logging.info(f"Cleaned hyperlinks and unwanted content from: {file_path}")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process PDFs with Marker and convert them to Markdown.")
    parser.add_argument("input_folder", help="Path to the folder containing PDF files.")
    parser.add_argument("output_folder", help="Path to the folder where processed Markdown files will be saved.")
    parser.add_argument("--workers", type=int, default=4, help="Number of parallel workers (default is 4).")

    args = parser.parse_args()

    # Uncomment if you want to process PDFs before cleaning
    process_pdfs(args.input_folder, args.output_folder, args.workers)

    # Post-process the Markdown files to clean unnecessary content
    clean_markdown_files(args.output_folder)
