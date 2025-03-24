from mcp.server.fastmcp import FastMCP
import httpx
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import logging
import argparse
from collections import Counter

# Set up logging with a basic configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize the FastMCP server with the name "nvd"
mcp = FastMCP("nvd")

# Load environment variables from keys.env file
load_dotenv('keys.env')

# NVD API base URL and API key from environment variables
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.environ['NVD_API_KEY']  # Ensure this is set in keys.env as NVD_API_KEY=your_key_here

# Helper function to fetch CVE data from the NVD API with flexible parameters
async def fetch_cve_data(params: dict) -> dict:
    """
    Fetches CVE data from the NVD API using the provided query parameters.
    Args:
        params (dict): Dictionary of query parameters for the NVD API.
    Returns:
        dict: JSON response from the API or an error message.
    """
    url = f"{NVD_API_BASE}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers={"apiKey": API_KEY})
        if response.status_code == 200:
            logging.info(f"Successfully fetched CVE data for params: {params}")
            return response.json()
        else:
            logging.error(f"Failed to fetch CVE data: {response.status_code} for params: {params}")
            return {"error": f"Failed to fetch CVE data: {response.status_code}"}

# Helper function to format CVE data into a readable string with enhanced error handling
def format_cve_details(cve):
    """
    Formats CVE details into a human-readable string with robust data handling.
    Args:
        cve (dict): The CVE data from the NVD API.
    Returns:
        str: Formatted string with CVE ID, description, CVSS score, and severity.
    """
    if "descriptions" not in cve or not cve["descriptions"]:
        description = "No description available."
    else:
        description = cve["descriptions"][0].get("value", "No description available.")
    
    cvss_v3 = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
    base_score = cvss_v3.get("baseScore", "N/A")
    severity = cvss_v3.get("baseSeverity", "N/A")
    
    return f"CVE ID: {cve.get('id', 'N/A')}\nDescription: {description}\nCVSS Base Score: {base_score}\nSeverity: {severity}"

# Helper function to search for CPEs by product name
async def search_cpes(product_name: str) -> list:
    """
    Searches for CPEs matching the given product name using the NVD API.
    Args:
        product_name (str): The name of the product to search for.
    Returns:
        list: List of CPE strings matching the product name.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={product_name}"
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers={"apiKey": API_KEY})
        if response.status_code == 200:
            data = response.json()
            return [product["cpe"]["cpeName"] for product in data.get("products", [])]
        else:
            logging.error(f"Failed to fetch CPEs for {product_name}: {response.status_code}")
            return []

# Helper function to find CPEs matching a specific version
def find_matching_cpes(cpes: list, version: str) -> list:
    """
    Filters CPEs to find those matching the specified version.
    Args:
        cpes (list): List of CPE strings.
        version (str): The version to match.
    Returns:
        list: List of CPE strings that match the version.
    """
    matching_cpes = []
    for cpe in cpes:
        parts = cpe.split(":")
        if len(parts) > 5 and parts[5] == version:
            matching_cpes.append(cpe)
    return matching_cpes

# Tool 1: Get details for a specific CVE by ID
@mcp.tool()
async def get_cve_details(cve_id: str) -> str:
    """
    Retrieves detailed information for a specific CVE by its ID.
    Args:
        cve_id (str): The CVE identifier (e.g., "CVE-2023-1234").
    Returns:
        str: Formatted details of the CVE or an error message.
    """
    params = {"cveId": cve_id}
    data = await fetch_cve_data(params)
    if "error" in data:
        return data["error"]
    cve = data.get("vulnerabilities", [{}])[0].get("cve", {})
    if not cve:
        return "No details found for this CVE."
    return format_cve_details(cve)

# Tool 2: Search for CVEs by keyword
@mcp.tool()
async def search_cves_by_keyword(keyword: str, limit: int = 10) -> str:
    """
    Searches for CVEs containing the specified keyword.
    Args:
        keyword (str): The keyword to search for in CVE descriptions.
        limit (int): Maximum number of results to return (default: 10).
    Returns:
        str: List of matching CVEs or a message if none are found.
    """
    params = {"keywordSearch": keyword, "resultsPerPage": limit}
    data = await fetch_cve_data(params)
    if "error" in data:
        return data["error"]
    cves = data.get("vulnerabilities", [])
    if not cves:
        return f"No CVEs found for keyword '{keyword}'."
    formatted_cves = [f"- {cve['cve']['id']}: {format_cve_details(cve['cve'])}" for cve in cves[:limit]]
    return f"Found {len(cves)} CVEs matching '{keyword}':\n" + "\n".join(formatted_cves)

# Tool 3: Get recent CVEs
@mcp.tool()
async def get_recent_cves(limit: int = 5, days_back: int = 7) -> str:
    """
    Fetches the most recent CVEs from the last specified number of days.
    Args:
        limit (int): Maximum number of CVEs to return (default: 5).
        days_back (int): Number of days to look back (default: 7).
    Returns:
        str: List of recent CVEs with publication dates and severity.
    """
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resultsPerPage": limit
    }
    data = await fetch_cve_data(params)
    if "error" in data:
        return data["error"]
    cves = data.get("vulnerabilities", [])
    if not cves:
        return f"No CVEs found in the last {days_back} days."
    formatted_cves = [f"- {cve['cve']['id']}: Published: {cve['cve']['published']}, Severity: {format_cve_details(cve['cve']).split('Severity: ')[1]}" for cve in cves[:limit]]
    return f"{len(cves)} most recent CVEs (last {days_back} days):\n" + "\n".join(formatted_cves)

# Tool 4: Filter CVEs by severity
@mcp.tool()
async def filter_cves_by_severity(severity: str, limit: int = 10) -> str:
    """
    Filters CVEs by their CVSS v3 severity level.
    Args:
        severity (str): Severity level (e.g., "LOW", "MEDIUM", "HIGH", "CRITICAL").
        limit (int): Maximum number of CVEs to return (default: 10).
    Returns:
        str: List of CVEs matching the severity or an error message.
    """
    valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if severity.upper() not in valid_severities:
        return f"Invalid severity level. Choose from: {', '.join(valid_severities)}."
    params = {"cvssV3Severity": severity.upper(), "resultsPerPage": limit}
    data = await fetch_cve_data(params)
    if "error" in data:
        return data["error"]
    cves = data.get("vulnerabilities", [])
    if not cves:
        return f"No CVEs found with severity '{severity}'."
    
    formatted_cves = []
    for cve in cves[:limit]:
        details = format_cve_details(cve['cve'])
        score = details.split('CVSS Base Score: ')[1].split('\n')[0]
        description = details.split('Description: ')[1].split('\n')[0]
        formatted_cves.append(f"- {cve['cve']['id']}: Score: {score}, Description: {description}")
    
    return f"{severity.upper()} CVEs (top {len(cves)}):\n" + "\n".join(formatted_cves)

# Tool 5: Check for vulnerabilities in code dependencies
@mcp.tool()
async def check_code_vulnerabilities(input_data: dict) -> str:
    """
    Checks for vulnerabilities in the provided list of dependencies.
    Args:
        input_data (dict): A dictionary with a 'dependencies' key containing a list of {'name': str, 'version': str}.
    Returns:
        str: Summary of vulnerabilities found or a message if none are found.
    """
    dependencies = input_data.get("dependencies", [])
    if not dependencies:
        return "No dependencies provided to check for vulnerabilities."

    all_vulnerabilities = []
    for dep in dependencies:
        product_name = dep.get("name")
        version = dep.get("version")
        if not product_name or not version:
            logging.warning(f"Skipping invalid dependency entry: {dep}")
            continue
        cpes = await search_cpes(product_name)
        matching_cpes = find_matching_cpes(cpes, version)
        for cpe in matching_cpes:
            params = {"cpeName": cpe}
            data = await fetch_cve_data(params)
            if "vulnerabilities" in data:
                all_vulnerabilities.extend(data["vulnerabilities"])

    if not all_vulnerabilities:
        return "No vulnerabilities found in the provided dependencies."

    severity_counts = Counter()
    for vuln in all_vulnerabilities:
        cve = vuln["cve"]
        severity = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
        severity_counts[severity] += 1

    summary = f"Found {len(all_vulnerabilities)} vulnerabilities: "
    summary += ", ".join(f"{count} {severity}" for severity, count in severity_counts.items())
    return summary

# Run the server with configurable transport
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NVD MCP Server - Connects to the National Vulnerability Database")
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "http"],
        help="Transport mechanism for the MCP server (default: stdio)"
    )
    args = parser.parse_args()
    logging.info(f"Starting NVD MCP server with transport: {args.transport}")
    mcp.run(transport=args.transport)