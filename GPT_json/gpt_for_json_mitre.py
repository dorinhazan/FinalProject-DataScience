import json
import openai
import pandas as pd
import os
from io import StringIO

# Set your OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")

# File paths
input_file_path = "/ics-attack-16.1.json"
output_folder = "/Users/nettayaakobi/Desktop/Final_project_codes/FinalProject-DataScience"
filtered_file_path = f"{output_folder}/filtered_descriptions.json"
output_csv_path = f"{output_folder}/analyzed_observables.csv"


# Step 1: Filter the JSON file
def filter_json(input_path, output_path):
    if os.path.exists(output_path):
        print(f"Filtered JSON file already exists at {output_path}. Skipping filtering step.")
        # Load the existing filtered JSON
        with open(output_path, "r") as existing_file:
            return json.load(existing_file)

    print("Starting to filter the JSON file...")
    with open(input_path, "r") as file:
        data = json.load(file)
    filtered_descriptions = [
        {"description": obj["description"]}
        for obj in data.get("objects", [])
        if obj.get("type") == "relationship" and obj.get("source_ref", "").startswith("malware--")
    ]
    with open(output_path, "w") as output_file:
        json.dump(filtered_descriptions, output_file, indent=4)
    print(f"Filtering completed. {len(filtered_descriptions)} descriptions were saved to {output_path}.")
    return filtered_descriptions


# Step 2: Prepare and send the request to OpenAI
def analyze_with_openai(filtered_data, prompt_template):
    print("Preparing to send the filtered data to OpenAI for analysis...")
    # Convert filtered JSON into text for input
    filtered_text = json.dumps(filtered_data, indent=4)
    # Combine the prompt template with the filtered text
    full_prompt = f"{prompt_template}\n\nJSON Input:\n{filtered_text}"
    print("Sending the request to OpenAI...")
    # Send the request to OpenAI
    response = openai.ChatCompletion.create(
        model="o1-mini",
        messages=[
            {"role": "user", "content": full_prompt}
        ],
    )
    print("Received response from OpenAI.")
    # Extract the result (the CSV content as text)
    return response["choices"][0]["message"]["content"]


# Step 3: Parse and save the result
def save_as_csv(content, output_path):
    print("Processing and saving the response content as a CSV file...")

    # Remove code fence lines and empty lines
    lines = [line for line in content.splitlines() if "```" not in line and line.strip()]

    cleaned_content = "\n".join(lines)

    csv_data = StringIO(cleaned_content)

    try:
        df = pd.read_csv(csv_data, sep=",", engine="python", quotechar='"', on_bad_lines='skip')
        if df.shape[1] != 5:
            print(f"Warning: Expected 5 columns but got {df.shape[1]}. Check for malformed lines.")
        df.to_csv(output_path, index=False)
        print(f"CSV file saved to {output_path}.")
    except Exception as e:
        print("Error while parsing CSV:", e)
        print("Full response content:")
        print(content)


# Main function
def main():
    print("Starting the process...")
    prompt_template = """
    You will be given a json file from mitre attack site, the file will contain the following key and values:
    ```{
    “description”: “…”}```
    
    Your mission is to analyze the file, identify, check the context of the element:
    
    fully_described_observables: data objects, physical objects, code snippets, commands mentioned in the provided text snippet. Definition for fully_described_observables: Fully described data elements are those for which the snippet provides enough specific details (e.g., name, type, distinctive property) to distinguish them from general mentions. Fully described physical objects are those explicitly identified with sufficient, unique descriptive information (e.g., exact name, location, or specific function) beyond a generic label. Commands – please provide full commands (e.g., shell commands, sql commands, linux commands such as sudo)
    
    Insufficient Observables: items that are only mentioned in passing or without sufficient details (e.g., generic references like “remote controller device,” “man-in-the-middle technique,” “spoofed signals,” unless the snippet explicitly provides additional distinguishing data such as brand names, specific versions, unique identifiers, or elaborated context)
    
    You must not skip or overlook any observables. If you are unsure whether something is an observable, err on the side of including it as an insufficient_observable if it lacks detail, or as a fully_described_observable if the description provides enough unique identifiers or details.
    
    How to Decide the Category:
    
    fully_described_observables:
    
    They must have enough detail to be uniquely identified. Examples:
    An IP address or domain name (e.g., 192.168.0.1, malicious-domain.com)
    A full code block enclosed in triple backticks
    A registry key path (e.g., HKEY_LOCAL_MACHINE\Software\Microsoft)
    A specifically named device or model
    A command or a set of commands that appear in the snippet
    insufficient_observables:
    
    Items referenced only in passing or without enough details to identify them clearly. Examples:
    Generic mentions like “a remote controller device” with no further details
    “malware” without name or type
    “spoofed signals” or “man-in-the-middle technique” without specifics
    Instructions: Your output will be a csv table with the following columns:
    
    Observable Type (insufficient or fully described) – as described above
    Observable Value
    Classification
    Notes
    context text
    
    For each fully described observables data objects, physical objects, code snippets, commands mentioned in the provided text snippet you find:
    
    Observable Value: The specific name or description exactly as stated (or closely paraphrased) in the snippet.
    Classification: it is the high-level category of the observables’s type. For example, "ICS Command", "Software/Tool", "Network Entity", "PLC", "Code snippet", etc. Please pay attention – if the observables are from a speific type for example: “SHA256”, “MD5” you will classify both of them as hash function and provide the specific type in the “notes”.
    Notes: there are three cases for this files:
    If additional important details are mentioned in the report: Include these details concisely in the Notes field to provide context or clarify the observable's significance. For example, specify associated parameters, unique identifiers, use cases, or any distinguishing characteristics.
    If no additional details are provided, but you are familiar with the observable type: Add a brief explanation or description of the observable to enhance understanding.
    "A PLC (Programmable Logic Controller) is used to automate industrial processes, typically in manufacturing or utility control systems."
    "ICS commands are instructions executed within industrial control systems to manage operations like controlling valves or monitoring system states."
    If no details are available and the observable type is unfamiliar or cannot be expanded upon: Leave the Notes field empty to avoid speculative or incorrect information.
    For each Insufficient Observable you find in the snippet, provide only:
    
    Observable’s value: The value of the item exactly as stated in the snippet.
    Notes: same instructions as in fully described observables, you can also provide a general note if you think it it valuable for this observable
    Classification:if there is  specific Classification as in the fully described obserevables then write it, else give a general classifiction of this observable. for ex:
    For the Insufficient Observable does not have a classification – if you find a relevant one please add it, otherwise you keep it null
    
    Thoroughness Check (to minimize missing observables)
    Parse the entire description carefully, line by line, and look for any mention of potential observables, including:
    Malware references (e.g., generic “malware,” “virus,” “trojan,” “ransomware,” “worm,” or specific malware names).
    Commands: shell commands, PowerShell commands, SQL statements, Linux commands (e.g., sudo), Windows utilities (e.g., netsh, ipconfig, regedit), or any code snippet references.
    Protocols (e.g., HTTP, SMB, S7comm, Modbus, OPC UA) and any unique ICS protocol references.
    Vulnerabilities (e.g., CVE numbers) or references to ICS attacks or CVE IDs.
    Registry keys or system paths (e.g., HKEY_LOCAL_MACHINE, /etc/passwd).
    Physical or brand references (e.g., “Omron PLC,” “Siemens S7-1200,” “Rockwell Automation controller”).
    Unique context references (e.g., “Triton,” “Stuxnet,” “IT networks,” “industrial networks,” or any brand or version detail).
    If you are not certain whether a mention is an observable, classify it as an Insufficient Observable (unless the snippet provides enough detail to classify it as fully described).
    
    context text: Provide a short snippet or sentence from the original description that shows where this observable appears. If it’s a long sentence, you may truncate, but keep enough text to illustrate the reference.
    
    Output Format:
    The final output must be only a CSV table (no extra commentary). The header row must appear exactly as:
    Observable Type,Observable Value,Classification,Notes,context text
    Each subsequent row represents one observable, with exactly four columns separated by commas. Important: If Classification or Notes contain commas, wrap that entire field in double quotes to keep CSV structure intact. For example:
    Fully Described,KillDisk,"Software/Tool, MITRE ID S0067","KillDisk is known destructive malware"
    Use commas as the delimiter between columns. Include all observables in the output with no truncation (no “...” at the end). Ensure each row is on its own line. No extra commentary or text beyond the CSV table itself is allowed.
    
    Important: Do not wrap the CSV output in triple backticks or any code fence. Only return the CSV lines.
    """


    # Step 1: Filter the JSON file
    filtered_data = filter_json(input_file_path, filtered_file_path)

    # Step 2: Send to OpenAI and get analysis
    analysis_result = analyze_with_openai(filtered_data, prompt_template)

    # Step 3: Save result as a CSV file
    save_as_csv(analysis_result, output_csv_path)
    print("Process completed successfully!")


# Execute the main function
if __name__ == "__main__":
    main()
