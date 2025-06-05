# VulnScraper

A fast and efficient vulnerability exploit scraper for CTF players and security testers. This tool helps quickly find exploit information based on service versions or vulnerability details from various online sources.

## Features

- Fast asynchronous web scraping
- Multiple source support:
  - MITRE CVE Database
  - GitHub Security Advisories and Exploits
  - NVD Database (National Vulnerability Database)
  - CVE.org Database
  - Exploit-DB
  - CVE Details
- Rich console interface with real-time progress tracking
- Smart result filtering and deduplication
- CVSS score and severity information
- Export results in JSON format
- Rate limiting and error handling

## Installation

There are two ways to install VulnScraper:

### Method 1: Direct Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/VulnScraper.git
cd VulnScraper
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Method 2: Using setup.py

1. Clone the repository:
```bash
git clone https://github.com/yourusername/VulnScraper.git
cd VulnScraper
```

2. Install using pip in editable mode:
```bash
pip install -e .
```

## Usage

### Basic Usage

Search for vulnerabilities related to a specific software version:
```bash
python -m src.vuln_scraper --search "apache 2.4.49"
```

### Advanced Usage

1. Search and export results to a JSON file:
```bash
python -m src.vuln_scraper --search "apache 2.4.49" --output results.json
```

2. Search for specific CVE:
```bash
python -m src.vuln_scraper --search "CVE-2021-41773"
```

3. Search for product vulnerabilities:
```bash
python -m src.vuln_scraper --search "wordpress plugin contact form 7"
```

### Output Format

The tool provides a rich console output with:
- Real-time progress tracking
- Color-coded CVSS scores
- Detailed vulnerability information
- References and exploit links
- Source attribution for each result

Results include:
- CVE ID (when available)
- CVSS Score/Severity
- Description
- Product and Version information
- References and URLs
- Source information

## GitHub Authentication (Optional)

To increase GitHub API rate limits, you can add your GitHub token using either of these methods:

1. Generate a GitHub Personal Access Token:
   - Go to GitHub Settings → Developer Settings → Personal Access Tokens
   - Generate a new token with 'public_repo' scope

2. Add the token using one of these methods:
   - Environment Variable (Recommended):
     ```bash
     # On Linux/macOS
     export GITHUB_TOKEN="your_token_here"
     
     # On Windows (PowerShell)
     $env:GITHUB_TOKEN="your_token_here"
     ```
   - Direct Code Configuration:
     - Open `src/vuln_scraper.py`
     - Replace `github_token = None` with `github_token = "your_token_here"`
     - Note: This method is not recommended for shared or public repositories

## Disclaimer

This tool is intended for educational and legitimate security testing purposes only. It only aggregates publicly available information from security databases. Users are responsible for using this tool in compliance with applicable laws and regulations.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.