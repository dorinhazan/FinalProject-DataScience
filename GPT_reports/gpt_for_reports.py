import os
import re
import json
import time
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Define base directories
base_path = "/Users/nettayaakobi/Desktop/ICS_REPORTS/ICS_MARKDOWNs"

prompt_template = """
You are a helpful assistant for identifying observables in text snippets.

Task:
You will be given a text snippet converted from a markdown file which is a CTI report. Your mission is to analyze the snippet and identify and list all observables (artifacts) in the text. Then, for each artifact you find, classify and provide the details as specified below.

Definitions:
1. Mentioned Observable - The artifact is referenced in a general or vague way, but without any specific or distinguishing details (like brand names, specific versions, unique identifiers, or an elaborated contextafterwards).These kind of observables are non-searchable.  Example: "remote controller device", "man-in-the-middle technique", "spoofed signals".
2. Described Observable - Notable specific or distinguishing details about the artifact are described in the text. but without sufficient unique information that would allow to detect it.These kind of observables are non-searchable.
3. Actionable Observable - The artifact is fully described with sufficient unique or specific information that would allow detecting it, these kinds of observables are searchable. The artifact can be used or executed immediately (e.g., an exact command, URL, api function, or file path), or the artifact requires additional data or some form of computation before it can be used or executed (e.g., a parameterized script, a hash that needs decoding, etc.).
4. STIX Supported -  This evaluates whether the type of this artifact is documented as STIX Cyber Observables. Some Observables may not be documented in STIX, such as ICS commands, ICS Tags, API calls and more.
5. Proprietary Artifact - Indicates whether the artifact relies on open standards or proprietary technology. Possible values: Open/Standard Technology, Proprietary-Documented Technology, or Proprietary-Undocumented Technology.

Instructions
1. Read the procedure description provided to you carefully.
2. Identify each observable (artifact) mentioned.
3. For each artifact, fill out the following fields exactly:
	1.observable_value: The name or description of the artifact as it appears (or a closely paraphrased version if needed).
	2.artifact_details: One of the following: "Mentioned" (for Mentioned Observable), "Described" (for Described Observable), "Actionable"(for an Actionable Observable).
	3. data_source: Indicate where this artifact could be observed or collected (e.g., network logs, system logs, ICS data, etc.).
	4. classification: This specifies what is the type of the artifact, For example, "ICS Command", "Software/Tool", "Network Entity", "PLC", "Code snippet", etc.
	5. STIX_supported: If supported in STIX, write: "Full: <STIX_Object_Name>". Otherwise, write: "No".
	6. proprietary_artifact: One of the following: "Open/Standard Technology", "Proprietary-Documented Technology", "Proprietary-Undocumented Technology"
	7. parser: If the artifact and its data source use a known network or file format with a publicly available parser, list the parser name(s). If no known parser exists, write "None"
	8. notes: Any extra comments or context, if needed. Otherwise, set this to "None".

Response Format:
 In your response, you should return a JSON format as follows:
 {
	"observables":[
		{"observable_value": <VAL>,
		 "artifact_details": <choose one of the options:["Mentioned", "Described", "Actionable"]>,
		 "data_source":<the data source this artifact can be found in, as mentioned in the instructions above>,
		 "classification":<the observable classification as mentioned above>,
		 "STIX_supported":<as mentioned in the instructions above>,
		 "proprietary_artifact":<choose one of the options:["Open/Standard Technology", "Proprietary-Documented Technology", "Proprietary-Undocumented Technology"]>,
		 "parser": <as mentioned in the instructions above>,
		 "notes": <additional notes in string format, default value should be None>},
		 ...
	] // list of all observables found in the description
 } // Do not output any additional text outside this JSON.

Important:

1. Do not omit any observable you encounter.
2. If multiple observables are present, list them all (each unique item must be captured).
3. For code snippets, include the full code including triple backticks.
4. For commands, include the full command (for example, those that use 'sudo').
5. **Note:** Picture references (e.g., _page_5_Picture_0.jpeg) should not be considered as observables.
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
                    response = send_to_openai(section_prompt)
                    raw_response = response.choices[0].message.content

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
