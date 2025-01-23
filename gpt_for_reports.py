import os
import openai
import time
import json
# Set your API key
openai.api_key = os.getenv("OPENAI_API_KEY")
# Define base directories
base_path = "/Users/nettayaakobi/Desktop/ICS_REPORTS/ICS_MARKDOWNs"

# Prompt to send to GPT

prompt_template = """You will be given a text snippet converted from markdown file which is a CTI report. Your mission is to analyze each file, identify, check the context of the element and divide it to the following categories:
1. fully_described_observables: data objects, physical objects, code snippets, commands mentioned in the provided text snippet. 
Definition for fully_described_observables:
1.1 Fully described data elements are those for which the snippet provides enough specific details (e.g., name, type, distinctive property) to distinguish them from general mentions. 
1.2 Fully described physical objects are those explicitly identified with sufficient, unique descriptive information (e.g., exact name, location, or specific function) beyond a generic label.
1.3 Regarding code snippets, please provide the full code in the observable_value field (the code snippet typically starts and end with ``` - you can omit it this is just the start and end sign).
1.4	 Commands – please provide full commands (e.g., shell commands, sql commands, linux commands such as sudo)

2	Insufficient Observables: items that are only mentioned in passing or without sufficient details (e.g., generic references like “remote controller device,” “man-in-the-middle technique,” “spoofed signals,” unless the snippet explicitly provides additional distinguishing data such as brand names, specific versions, unique identifiers, or elaborated context)

You must not skip or overlook any observables. If you are unsure whether something is an observable, err on the side of including it as an insufficient_observable if it lacks detail, or as a fully_described_observable if the snippet provides enough unique identifiers or details.
How to Decide the Category
1.	fully_described_observables:
o	They must have enough detail to be uniquely identified.
o	Examples:
	An IP address or domain name (e.g., 192.168.0.1, malicious-domain.com)
	A full code block enclosed in triple backticks
	A registry key path (e.g., HKEY_LOCAL_MACHINE\Software\Microsoft)
	A specifically named device or model
	A command or a set of commands that appear in the snippet
2.	insufficient_observables:
o	Items referenced only in passing or without enough details to identify them clearly.
o	Examples:
	Generic mentions like “a remote controller device” with no further details
	“malware” without name or type
	“spoofed signals” or “man-in-the-middle technique” without specifics

Instructions:
For each fully described observables data objects, physical objects, code snippets, commands mentioned in the provided text snippet you find, provide only:
1. Observable Value: The specific name or description exactly as stated (or closely paraphrased) in the snippet.
2. Classification: it is the high-level category of the obseravables’s type. For example, "ICS Command", "Software/Tool", "Network Entity", "PLC", "Code snippet", etc.  Please pay attention – if the observables are from a speific type for example: “SHA256”, “MD5” you will classify both of them as hash function and provide the specific type in the “notes”.
3. Notes: there are three cases for this files:
If additional important details are mentioned in the report:
•	Include these details concisely in the Notes field to provide context or clarify the observable's significance. For example, specify associated parameters, unique identifiers, use cases, or any distinguishing characteristics.
If no additional details are provided, but you are familiar with the observable type:
•	Add a brief explanation or description of the observable to enhance understanding. This description should include its purpose, functionality, or common applications. For example:
o	"A PLC (Programmable Logic Controller) is used to automate industrial processes, typically in manufacturing or utility control systems."
o	"ICS commands are instructions executed within industrial control systems to manage operations like controlling valves or monitoring system states."
If no details are available and the observable type is unfamiliar or cannot be expanded upon:
•	Leave the Notes field empty to avoid speculative or incorrect information.
4. report_name: The name of the report where this observable was found.
5. text/code_section: The specific text or code snippet section in the relevant context, so we can see the observable's context in the content of the text.
 For example, if the observable is inside a table please provide the full table, if it is in another context please analyze the text and attach the relavant content to the observable.

For each Insufficient Observable you find in the snippet, provide only:
1. Mentioned Value: The value of the item exactly as stated in the snippet.
2. Notes: same instructions as in fully described observables
3.report_name: The name of the report.
4.text/code_section: The specific text or code snippet section in the relevant context.

Response Format:
{
  "fully_described_observables": [
    {
      "observable_value": "<VAL>",
      "classification": "<the observable classification>",
      "notes": "<any additional info or explanation>",
      "report_name": "<the name of the report>",
      "text/code_section": "<the section/snippet name or ID if available>",
    },
    ...
  ],
  "insufficient_observables": [
    {
      "mentioned_value": "<VAL>",
      "notes": "<explanation if known, else blank>",
      "report_name": "<the name of the report>",
      "text/code_section": "<the section/snippet name or ID if available>",
    },
    ...
  ]
}

for example:
{"fully_described_observables": [
            {
                "observable_value": "https://www.intego.com/antivirus-mac-internet-security",
                "classification": "URL",
                "notes": "Official site of the antivirus developer",
                "report_name": "Calisto Trojan for macOS",
                "text/code_section": "The software package appears to be invalid. Please download a new package from https:// www.intego.com/antivirus-mac-internet-security"
            },
            ...
            ]
 "insufficient_observables": [ {...}
 }          

Key Points to Remember:
•	Do not omit any observable you encounter.
•	If multiple observables are present, list them all (even if they appear repetitive, ensure each unique item is captured).
•	Provide the full code for code snippets, including the triple backticks.
•	Provide the full command for commands mentioned in the snippet - please pay attention to sudo commands.
•	Double-check for anything that could be considered an observable. If it’s unclear, classify it under insufficient_observables.


Finally, output only the JSON object in the specified format—no extra commentary or text and please handle “\n” correctly so that it will be human readable (for example replae "\nsudo" in "sudo" only.
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


def send_to_openai(md_content):
    """Send the content of the markdown file to OpenAI's GPT model."""
    # Combine the prompt template and markdown content into a single string
    full_prompt = f"{prompt_template}\n\n{md_content}"

    response = openai.ChatCompletion.create(
        model="o1-mini",
        messages=[
            {"role": "user", "content": full_prompt}
        ],
    )
    return response


def main():

    # Locate all .md files
    md_files = find_md_files(base_path)
    print(f"Found {len(md_files)} markdown files.")

    total_start_time = time.time()

    # Process each file
    results = {}
    for md_file in md_files:
        print(f"Processing file: {md_file}")
        try:
            # Read the markdown content
            md_content = process_md_file(md_file)

            # Send the content to OpenAI
            response = send_to_openai(md_content)

            # Extract the raw response content
            raw_response = response['choices'][0]['message']['content']

            # Ensure the response is not empty
            if not raw_response.strip():
                raise ValueError(f"Empty response for file: {md_file}")

            # Clean the raw response (remove backticks and surrounding "```json" markers)
            cleaned_response = raw_response.strip("```").strip("json").strip()

            # Parse the cleaned JSON response
            parsed_response = json.loads(cleaned_response)

            # Add to results
            results[os.path.basename(md_file)] = parsed_response
        except Exception as e:
            print(f"Error processing file {md_file}: {e}")
            results[os.path.basename(md_file)] = {"error": str(e), "raw_response": raw_response}

    total_end_time = time.time()
    total_elapsed = total_end_time - total_start_time
    print(f"\nTotal processing time: {total_elapsed:.2f} seconds.")

    # Save the formatted JSON to a file
    output_file_path = "/Users/nettayaakobi/Desktop/Final_project_codes/FinalProject-DataScience/results-reports.json"
    with open(output_file_path, "w") as output_file:
        json.dump(results, output_file, indent=4)
    print(f"Results saved to {output_file_path}.")


if __name__ == "__main__":
    main()

