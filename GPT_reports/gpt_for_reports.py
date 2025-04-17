import os
import re
import json
import time
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Define base directories
base_path = "/Users/nettayaakobi/Desktop/ICS_REPORTS/validation"

prompt_template = """
You are a helpful assistant for identifying observables in CTI text snippets.

──────────────────────────────────────────────────
### Task

1. Read the snippet (converted from Markdown) carefully.
2. Extract **every observable** (artifact) mentioned—do **not** omit any.
3. For each observable, output a JSON object with the exact fields listed in the **Response format** section.

──────────────────────────────────────────────────
### Definitions

1. **Mentioned Observable**  
   *Vaguely referenced; lacks unique details; not searchable.*  
   e.g. "remote controller device", "spoofed signals".
2. **Described Observable**  
   *Has notable specifics, but still not unique enough for detection; not searchable.*
3. **Actionable Observable**  
   *Unique & specific* → a deterministic IDS/YARA/SIEM rule could match it with low FP.  
   *Immediately operable* **as-is** (exact URL/command/path/API) **or** after one simple transform (e.g., Base64 decode, hash lookup, parameter substitution).  
   *Searchable* and can drive automated response.  
4. **STIX Supported**  
   "Full" if the artifact’s type exists in STIX Cyber-Observable Objects; otherwise "No".
5. **Proprietary Artifact**  
   • Open/Standard Technology • Proprietary-Documented • Proprietary-Undocumented

──────────────────────────────────────────────────
### Rubric for choosing `artifact_details`

1. **Actionable check → "Actionable"**  
   Does the observable stand alone as a unique data value that can be matched exactly or after one deterministic transform?  
   • Yes → `artifact_details` = **"Actionable"**.

2. **Else, Described check → "Described"**  
   Does it contain distinguishing specifics but still lacks enough uniqueness for detection?  
   • Yes → `artifact_details` = **"Described"**.

3. **Else → "Mentioned"**  
   If neither of the above applies, treat it as **"Mentioned"**.

──────────────────────────────────────────────────
### Fields to produce for **every** observable

| Field                  | What to put                                                                                                |
| ---------------------- | ---------------------------------------------------------------------------------------------------------- |
| `observable_value`     | Exact string (or faithful paraphrase). Include full code/commands inside \`\`\` back-ticks if needed.      |
| `artifact_details`     | "Mentioned", "Described", or "Actionable".                                                                 |
| `data_source`          | Where it can be observed or collected (see cheat-sheet below).                                             |
| `classification`       | Short type label (e.g., "ICS Command", "URL", "Software/Tool").                                            |
| `STIX_supported`       | "Full: \<STIX\_Object\_Name>" **or** “No”.                                                                 |
| `proprietary_artifact` | "Open/Standard Technology", "Proprietary-Documented Technology", or "Proprietary-Undocumented Technology". |
| `parser`               | Known open-source/commercial parser name(s) for the data format, else "None".                              |
| `notes`                | Any extra comments or context, if needed. Otherwise, set this to "None".                                                                                   |

──────────────────────────────────────────────────
### Common `data_source` cheat-sheet

Network traffic • Netflow • PCAP • DNS logs • Web proxy logs • Endpoint (EDR) logs • System logs (Windows Event, syslog) • ICS historian • PLC ladder logic • Firewall logs • Cloud API audit logs • Memory dump • None (if not observable via telemetry)

──────────────────────────────────────────────────
### Response format (return **only** this JSON)  

```json
{
  "observables": [
    {
      "observable_value": "<VAL>",
      "artifact_details": "Mentioned | Described | Actionable",
      "data_source": "<text>",
      "classification": "<text>",
      "STIX_supported": "<text>",
      "proprietary_artifact": "Open/Standard Technology | Proprietary-Documented Technology | Proprietary-Undocumented Technology",
      "parser": "<text>",
      "notes": "<text>"
    }
    // … repeat for each observable
  ]
}
```
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
        # print(sections)
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

def send_to_openai(prompt_template, section):
  completion = client.chat.completions.create(
  model="o3-mini-2025-01-31",
  messages=[
      {"role":"developer", "content": prompt_template},
      {"role":"user", "content": section}
  ],
  reasoning_effort = "high",
  response_format = { "type": "json_object" }
  )
  result = completion.choices[0].message.content
  return result

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
                "Actionable": [],
                "Described": [],
                "Mentioned": []

            }

            # Process each section separately
            for idx, section in enumerate(sections):
                # Create a prompt for the current section including an identifier for the section.
                section_prompt = f"{prompt_template}\n\nSection {idx + 1}:\n{section}"
                print(f"Processing section {idx + 1} of {len(sections)}")
                print(f"Section {section}")
                try:
                    raw_response = send_to_openai(prompt_template, section_prompt)

                    if not raw_response.strip():
                        raise ValueError(f"Empty response for section {idx + 1} in file {md_file}")

                    # Clean the raw response by removing potential markdown formatting.
                    cleaned_response = raw_response.strip("```").strip("json").strip()
                    parsed_response = json.loads(cleaned_response)

                    if "observables" in parsed_response:
                        for obs in parsed_response["observables"]:
                            category = obs.get("artifact_details")
                            if category in aggregated_result:
                                aggregated_result[category].append(obs)


                except Exception as section_error:
                    print(f"Error processing section {idx + 1} of {md_file}: {section_error}")
                    continue

            # Remove duplicates from both observables lists.
            aggregated_result["Actionable"] = remove_duplicates(aggregated_result["Actionable"])
            aggregated_result["Described"] = remove_duplicates(aggregated_result["Described"])
            aggregated_result["Mentioned"] = remove_duplicates(aggregated_result["Mentioned"])


            results[os.path.basename(md_file)] = aggregated_result

        except Exception as e:
            print(f"Error processing file {md_file}: {e}")
            results[os.path.basename(md_file)] = {"error": str(e)}

    total_end_time = time.time()
    total_elapsed = total_end_time - total_start_time
    print(f"\nTotal processing time: {total_elapsed:.2f} seconds.")

    # Save the aggregated results to a JSON file.
    output_file_path = "results-reports-new-prompt.json"
    with open(output_file_path, "w") as output_file:
        json.dump(results, output_file, indent=4)
    print(f"Results saved to {output_file_path}.")

if __name__ == "__main__":
    main()
