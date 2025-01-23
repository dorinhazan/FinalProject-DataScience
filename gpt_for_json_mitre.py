import os
import openai

# Set your API key
openai.api_key = os.getenv("OPENAI_API_KEY")

# Define base directories
base_path = r"/Users/nettayaakobi/Desktop/Final_project_codes/FinalProject-DataScience"

# Prompt to send to GPT
prompt_template = """You will be provided with a md file containing rows of data. Each row includes text snippets with specific formatting. Your task is to identify and categorize the observables within each text snippet according to the criteria below. 

Definitions of Observables: 
1. Fully Described Observables: These are data objects, physical objects, code snippets, or commands that are sufficiently detailed to distinguish them from general references. 
    Examples include: o Data Elements: Named items with specific details or unique identifiers (e.g., "file name," "hash type"). 
                      o Physical Objects: Objects explicitly identified with unique descriptions (e.g., "Brand X device"). 
                      o Code Snippets: Full code snippets included in the text. o Commands: Fully described commands (e.g., shell commands, SQL commands). 
2. Insufficient Observables: Items mentioned without sufficient detail to uniquely identify them, such as generic references (e.g., "spoofed signals" or "remote controller device") unless additional distinguishing information is provided (e.g., brand names, versions, or specific context). 

Rules for Identifying Observables: 
1. Step 1: Does the sentence contain information related to attack components? 
    o If no, it is not an observable. o If yes, proceed to Step 2. 
2. Step 2: Were the components used, modified, or damaged by malware to achieve the attack's main goal? 
    o If no, it is not an observable. 
    o If yes, proceed to Step 3. 
3. Step 3: Can the usage of these components be detected as irregular behavior during the attack? 
    o If no, it is not an observable. 
    o If yes, it qualifies as an observable. 


Instructions for Output: For each observable found in the text snippets: 
1. Observable’s Type: Specify whether the observable is a "Fully Described Observable" or an "Insufficient Observable" based on the provided definitions. 
2. Observable Value: Provide the exact name or description of the observable from the text. 
3. Classification: Assign the observable to a high-level category, such as: o "ICS Command," "Software/Tool," "Network Entity," "PLC," "Code Snippet," or specific types like "SHA256" or "MD5" (classified as "Hash Function"). 
4. Notes: 
    o If additional details are provided in the text, include them concisely in the Notes field (e.g., associated parameters, identifiers, or use cases). 
    o If no details are provided but you are familiar with the type, add a brief explanation of its purpose, functionality, or applications. 
    o Leave the field empty if no details are available or the observable type is unfamiliar. 
5. Context Text: Add the original text snippet containing the observable for reference. Information to Exclude: • Ignore URLs within parentheses following the observable name in square brackets (e.g., [Backdoor.Oldrea](https://attack.mitre.org/software/S0093)). • Ignore citations in parentheses (e.g., (Citation:...)). 

Output Format: Generate an Excel file with the following columns: 1. Observable’s Type: Either "Fully Described Observable" or "Insufficient Observable." 2. Observable Value: The specific name or description of the observable. 3. Classification: The high-level category of the observable. 4. Notes: Additional details or explanations (if available or applicable). 5. Context Text: The original text snippet from the entry."""


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
    import os
    import json

    # Locate all .md files
    md_files = find_md_files(base_path)
    print(f"Found {len(md_files)} markdown files.")

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

    # Save the formatted JSON to a file
    output_file_path = "results.json"
    with open(output_file_path, "w") as output_file:
        json.dump(results, output_file, indent=4)
    print(f"Results saved to {output_file_path}.")


if __name__ == "__main__":
    main()


