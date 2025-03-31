# NVD MCP Server

Stay ahead of security threats without breaking your flow. The **NVD MCP Server** is your gateway to the National Vulnerability Database (NVD), seamlessly integrated into AI-powered development environments like Windsurf. Ask questions in plain English, get real-time vulnerability data, and keep your code secure—all from within your IDE. Built on the Model Context Protocol (MCP), this server bridges conversational queries with the NVD's extensive security database, empowering developers to stay informed effortlessly.

---

## Features

- **CVE Details Lookup**: Ask "What's the scoop on CVE-2023-1234?" and get a detailed breakdown—description, CVSS score, severity, and more.
- **Keyword Search**: Type "Find CVEs related to Apache" to uncover vulnerabilities tied to specific technologies or keywords.
- **Recent CVEs**: Use "Show me the latest CVEs from the past week" to stay updated on newly reported vulnerabilities.
- **Severity Filtering**: Filter with "List critical vulnerabilities" to zero in on the most urgent security risks.

---

## Requirements

- **Python 3.8 or higher**
- **Dependencies**:
  - `mcp`
  - `httpx`
  - `python-dotenv`

Install them with:
```pip install mcp httpx python-dotenv```

## Installation

1. Clone the repository:
```git clone https://github.com/sockcymbal/nvd-mcp-server.git
cd nvd-mcp-server
```
2. Set up a virtual environment:
```python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. Install dependencies:
  - pip install -r requirements.txt
4. Configure your NVD API key:
- Request a key from NVD API Key Request: https://nvd.nist.gov/developers/request-an-api-key
- Create a keys.env file in the project root with: NVD_API_KEY=your_api_key_here

## Usage
1. Launch the server:
- python nvd_mcp.py --transport stdio
2. Connect your client/IDE/agent to communicate with this MCP server.
  - Eg, if you're on Claude Desktop, go to Claude > Settings > Developer > Edit Config > claude_desktop_config.json to include the following:
```
{
  "mcpServers": {
    "nvd": {
      "command": "uv",
      "args": ["--directory", "/Path to nvd_mcp directory", "run", "nvd_mcp.py"]
    }
  }
}
```
3. Query away with natural language:
- "What's the deal with CVE-2023-1234?"
Returns detailed CVE info, like description and severity.

- "Any recent critical vulnerabilities?"
Lists the latest CVEs with critical severity.

- "Search for CVEs mentioning Apache."
Shows vulnerabilities related to Apache.

## Configuration
- API Key: Store your NVD API key securely in keys.env as NVD_API_KEY=your_api_key_here.

- Transport Mechanism:
  - Default: --transport stdio for local use.
  - For networked setups, use --transport http (ensure proper security, like HTTPS).

## Contributing
We’d love your help to make this project even better!

## Acknowledgments
- Anthropic for the MCP framework.
- NIST for maintaining the NVD.
- You for checking out this project!

# NVD MCP Server
[![Stars](https://img.shields.io/github/stars/sockcymbal/nvd-mcp-server?style=social)](https://github.com/sockcymbal/nvd-mcp-server/stargazers)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Issues](https://img.shields.io/github/issues/sockcymbal/nvd-mcp-server)](https://github.com/sockcymbal/nvd-mcp-server/issues)

Stay ahead of security threats without breaking your flow...


### Disclaimer
This is a third-party integration and not made by NIST. Made by Sockcymbal.
