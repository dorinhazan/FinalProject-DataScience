import re

def check_markdown_content(markdown_file):
    """
    Check for unwanted content in a Markdown file such as hyperlinks, annotations,
    headers, footers, JavaScript, and hidden text.
    Args:
        markdown_file (str): Path to the Markdown file to be checked.
    """
    with open(markdown_file, "r", encoding="utf-8") as file:
        content = file.read()

    # Patterns to detect unwanted content
    patterns = {
        "hyperlinks": r'http[s]?://\S+',  # Detect standalone URLs
        "annotations": r'\[.*?\]\(.*?\)',  # Detect Markdown-style annotations like [text](url)
        "hidden_text": r'<!--.*?-->',  # Detect HTML-style hidden comments
        "javascript": r'<script.*?>.*?</script>',  # Detect inline JavaScript blocks
        "headers_footers": r'(Recommended Practice|Homeland Security|Page \d+)'  # Common headers/footers
    }

    print("Checking for unwanted content in Markdown...")
    results = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        results[name] = matches
        if matches:
            print(f"Found {name}: {matches[:5]}... ({len(matches)} occurrences)")
        else:
            print(f"No {name} detected.")

    return results

# Example Usage
markdown_file_path = "/Users/apiiro/Desktop/ICS_MARKDOWNs/final-RP_ics_cybersecurity_incident_response_100609/final-RP_ics_cybersecurity_incident_response_100609.md"  # Replace with your Markdown file path
check_markdown_content(markdown_file_path)
