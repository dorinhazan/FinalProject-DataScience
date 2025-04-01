import os
import re
import json
import time
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Define base directories
base_path = "/Users/nettayaakobi/Desktop/ICS_REPORTS/ICS_MARKDOWNs"

# Prompt template remains the same
prompt_template = """You will be given a text snippet converted from a markdown file which is a CTI report. Your mission is to analyze the snippet and identify observables, 
then categorize each into one of two groups: fully_described_observables or insufficient_observables.

1. Fully Described Observables:
   - These include data objects, physical objects, code snippets, or commands that are mentioned with enough detail (such as specific names, types, distinctive properties) to uniquely identify them.
   - Examples:
       • An IP address or domain name (e.g., 192.168.0.1, malicious-domain.com)
       • A full code block enclosed in triple backticks
       • A registry key path (e.g., HKEY_LOCAL_MACHINE\Software\Microsoft)
       • A specifically named device or model
       • A command or set of commands (e.g., shell commands, SQL commands, Linux commands such as sudo)
   - Note: If the observable is of a specific type (for example, “SHA256” or “MD5”), classify it as a hash function and include the specific type in the “notes” field.

2. Insufficient Observables:
   - These are items mentioned in passing or without sufficient details to uniquely identify them.
   - Examples:
       • Generic mentions like “a remote controller device” with no additional details
       • “malware” without a specific name or type
       • “spoofed signals” or “man-in-the-middle technique” without further specifics
   - If you are unsure whether something is fully described, err on the side of including it as an insufficient observable.

Instructions for Output:

For each fully described observable, provide a JSON object with:
   1. observable_value: The exact name or description (or a close paraphrase) as stated in the snippet.
   2. classification: The high-level category (e.g., "ICS Command", "Software/Tool", "Network Entity", "PLC", "Code snippet", etc.).
   3. notes: Include any additional details or context if provided; if no further details are available but you are familiar with the observable type, add a brief explanation of its purpose, functionality, or common applications. Otherwise, leave this field empty.
   4. report_name: The name of the report where this observable was found.
   5. text/code_section: The specific text or code snippet context (e.g., the section, table, or code block) where the observable appears.

For each insufficient observable, provide a JSON object with:
   1. mentioned_value: The exact value as stated in the snippet.
   2. notes: Additional context or an explanation if known, or leave blank.
   3. report_name: The name of the report.
   4. text/code_section: The specific text or code snippet context in which the observable is mentioned.

Response Format:

Output only a JSON object in the following format (no extra commentary):

{
  "fully_described_observables": [
    {
      "observable_value": "<VAL>",
      "classification": "<the observable classification>",
      "notes": "<any additional info or explanation>",
      "report_name": "<the name of the report>",
      "text/code_section": "<the section/snippet name or ID if available>"
    },
    ...
  ],
  "insufficient_observables": [
    {
      "mentioned_value": "<VAL>",
      "notes": "<explanation if known, else blank>",
      "report_name": "<the name of the report>",
      "text/code_section": "<the section/snippet name or ID if available>"
    },
    ...
  ]
}

Example:
{
  "fully_described_observables": [
    {
      "observable_value": "https://www.intego.com/antivirus-mac-internet-security",
      "classification": "URL",
      "notes": "Official site of the antivirus developer",
      "report_name": "Calisto Trojan for macOS",
      "text/code_section": "The software package appears to be invalid. Please download a new package from https://www.intego.com/antivirus-mac-internet-security"
    }
  ],
  "insufficient_observables": [
    {
      "mentioned_value": "remote controller device",
      "notes": "",
      "report_name": "Calisto Trojan for macOS",
      "text/code_section": "Context mentioning a remote controller device"
    }
  ]
}

Important:

• Do not omit any observable you encounter.
• If multiple observables are present, list them all (each unique item must be captured).
• For code snippets, include the full code including triple backticks.
• For commands, include the full command (for example, those that use 'sudo').
• **Note:** Picture references (e.g., _page_5_Picture_0.jpeg) should not be considered as observables.
• Double-check for any elements that could be considered observables; if uncertain, classify as insufficient.

Finally, output only the JSON object in the specified format and ensure newline characters are correctly represented.
"""

def find_md_files(base_path):
    """Recursively find all .md files in the directory."""
    md_files = []
    for root, _, files in os.walk(base_path):
        for file in files:
            if file.endswith(".md"):
                md_files.append(os.path.join(root, file))
    return md_files

def process_md_file(md_file_path):
    """Read and convert .md file to plain text."""
    with open(md_file_path, 'r') as file:
        return file.read()

def split_into_sections(md_content):
    """
    Split the markdown content into logical sections using markdown headers.

    This function uses a regular expression to find headers (lines starting with '#' characters)
    and splits the content accordingly. If the file doesn't contain any headers, it returns the entire
    content as one section.
    """
    pattern = re.compile(r'^(#{1,6}\s.*)', re.MULTILINE)
    matches = list(pattern.finditer(md_content))
    sections = []
    if not matches:
        # No headers found, return the full content as one section.
        sections.append(md_content)
        print(sections)
        return sections

    # Add any content before the first header as its own section if present.
    if matches[0].start() > 0:
        sections.append(md_content[:matches[0].start()])

    # Split content based on header positions.
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(md_content)
        sections.append(md_content[start:end])
    print(sections)
    return sections

def send_to_openai(prompt_text):
    """Send the given prompt text to OpenAI's GPT model and return the response."""
    response = client.chat.completions.create(
        model="o3-mini-2025-01-31",
        messages=[
            {"role": "user", "content": prompt_text}
        ]
    )
    return response

def remove_duplicates(observables_list):
    """Remove duplicate dictionaries from a list of observables."""
    unique = []
    seen = set()
    for item in observables_list:
        # Convert dictionary to a JSON string for a consistent, hashable representation.
        item_str = json.dumps(item, sort_keys=True)
        if item_str not in seen:
            seen.add(item_str)
            unique.append(item)
    return unique

def main():
    # Locate all markdown files in the base directory.
    md_files = find_md_files(base_path)
    print(f"Found {len(md_files)} markdown files.")

    total_start_time = time.time()
    results = {}

    # Process each markdown file
    for md_file in md_files:
        print(f"Processing file: {md_file}")
        try:
            md_content = process_md_file(md_file)
            sections = split_into_sections(md_content)
            print(f"File split into {len(sections)} sections.")

            # Initialize an aggregated result for the current file
            aggregated_result = {
                "fully_described_observables": [],
                "insufficient_observables": []
            }

            # Process each section separately
            for idx, section in enumerate(sections):
                # Create a prompt for the current section including an identifier for the section.
                section_prompt = f"{prompt_template}\n\nSection {idx + 1}:\n{section}"
                print(f"Processing section {idx + 1} of {len(sections)}")
                print(f"Section {section}")
                try:
                    response = send_to_openai(section_prompt)
                    raw_response = response.choices[0].message.content

                    if not raw_response.strip():
                        raise ValueError(f"Empty response for section {idx + 1} in file {md_file}")

                    # Clean the raw response by removing potential markdown formatting.
                    cleaned_response = raw_response.strip("```").strip("json").strip()
                    parsed_response = json.loads(cleaned_response)

                    # Aggregate observables from the response.
                    if "fully_described_observables" in parsed_response:
                        aggregated_result["fully_described_observables"].extend(
                            parsed_response["fully_described_observables"]
                        )
                    if "insufficient_observables" in parsed_response:
                        aggregated_result["insufficient_observables"].extend(
                            parsed_response["insufficient_observables"]
                        )

                except Exception as section_error:
                    print(f"Error processing section {idx + 1} of {md_file}: {section_error}")
                    continue

            # Remove duplicates from both observables lists.
            aggregated_result["fully_described_observables"] = remove_duplicates(aggregated_result["fully_described_observables"])
            aggregated_result["insufficient_observables"] = remove_duplicates(aggregated_result["insufficient_observables"])

            results[os.path.basename(md_file)] = aggregated_result

        except Exception as e:
            print(f"Error processing file {md_file}: {e}")
            results[os.path.basename(md_file)] = {"error": str(e)}

    total_end_time = time.time()
    total_elapsed = total_end_time - total_start_time
    print(f"\nTotal processing time: {total_elapsed:.2f} seconds.")

    # Save the aggregated results to a JSON file.
    output_file_path = "/Users/nettayaakobi/Desktop/Final_project_codes/FinalProject-DataScience/results-reports.json"
    with open(output_file_path, "w") as output_file:
        json.dump(results, output_file, indent=4)
    print(f"Results saved to {output_file_path}.")

if __name__ == "__main__":
    main()
