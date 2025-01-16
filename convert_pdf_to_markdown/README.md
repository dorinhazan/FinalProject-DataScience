*Marker PDF to Markdown Conversion*
This guide outlines the steps to set up the environment and run the script for converting PDFs to Markdown files.

**Prerequisites**
Python 3.12 or higher installed.
Poetry package manager installed.
Ensure your system PATH is properly configured.

**Setup Instructions**
1. Clone the Repository
Clone the Marker repository from GitHub: `git clone https://github.com/VikParuchuri/marker.git`
`cd /<path_to_your_marker_repo_directory>/marker`
2. Install Poetry
If Poetry is not installed, install it using pip: `pip install poetry` , `poetry install` . `poetry shell`
3. Activate the environment `source /Users/apiiro/Library/Caches/pypoetry/virtualenvs/marker-pdf-tnhLY2bl-py3.12/bin/activate`
4. Install the marker-pdf Package: `pip install marker-pdf`
5. Running the Script:
   1. Export PATH (Optional)
      If needed, export the Poetry virtual environment path to your system PATH: `export PATH=$PATH:/Users/apiiro/Library/Caches/pypoetry/virtualenvs/marker-pdf-tnhLY2bl-py3.12/bin`
   2. Execute the Conversion Script: `python3 /<path-to-repo>/FinalProject-DataScience/convert_pdf_to_markdown /<path-to-repo>/ICS_PDFs //<path-to-repo>/ICS_MARKDOWNs  --workers 2`



