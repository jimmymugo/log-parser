import re
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt
import json
import requests
import time
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv('api_key')

pd.set_option('display.max_columns', None)
pd.set_option('display.max_colwidth', None)
pd.set_option('display.max_rows', None)
pd.set_option('display.width', None)

# Extended Log patterns for multiple log formats (Apache, Nginx, etc.)
log_patterns = {
    'apache': r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(\w+) (.+?) HTTP/[\d\.]+" (\d+) (\S+) "(.*?)" "(.*?)"?',
    'nginx': r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(\w+) (.+?) HTTP\/\d\.\d" (\d+) (\d+)',
    'common': r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(\w+) (.+?) HTTP/\d\.\d" (\d+) (\S+) "(.*?)" "(.*?)"',
    'combined': r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(\w+) (.+?) HTTP/\d\.\d" (\d+) (\S+) "(.*?)" "(.*?)" "(.*?)"',
}

def parse_logs(file_path, log_type="apache"):
    """Parse log file based on the specified log format."""
    logs = []
    unmatched_lines = []  # List to store unmatched lines
    log_pattern = log_patterns.get(log_type, log_patterns['apache'])  # Default to 'apache' if log_type is invalid

    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(log_pattern, line)
            if not match:
                unmatched_lines.append(line.strip())
                continue  # Skip lines that don't match

            # Unpack matched groups
            try:
                ip, timestamp, method, url, status, size, referrer, user_agent = match.groups()
            except ValueError:
                print(f"Warning: Skipping malformed line: {line}")
                continue

            # Handle missing or "-" values in the size, referrer, and user-agent fields
            size = None if size == '-' else int(size)
            referrer = None if referrer == '-' else referrer
            user_agent = None if user_agent == '-' else user_agent

            logs.append({
                'IP': ip,
                'Timestamp': timestamp,
                'Method': method,
                'URL': url,
                'Status': int(status),
                'Size': size,
                'Referrer': referrer,
                'User-Agent': user_agent
            })

    logs_df = pd.DataFrame(logs)

    # Optionally, print out unmatched lines for review
    if unmatched_lines:
        print(f"Unmatched lines ({len(unmatched_lines)}):")
        for unmatched in unmatched_lines:
            print(unmatched)

    # Check if any logs were parsed
    if logs_df.empty:
        print("No logs were parsed. Check the log format and regex.")
        exit(1)

    return logs_df

def detect_brute_force(logs, threshold=10):
    """Detect IPs with excessive failed login attempts (401 status)."""
    failed_attempts = logs[logs['Status'] == 401]
    attempts_by_ip = Counter(failed_attempts['IP'])
    brute_force_ips = [ip for ip, count in attempts_by_ip.items() if count > threshold]
    return brute_force_ips

def detect_frequent_404s(logs, threshold=20):
    """Detect IPs causing excessive 404 errors."""
    frequent_404s = logs[logs['Status'] == 404]
    errors_by_ip = Counter(frequent_404s['IP'])
    frequent_404_ips = [ip for ip, count in errors_by_ip.items() if count > threshold]
    return frequent_404_ips

def detect_sql_injections(logs):
    """Detect potential SQL injection attempts in URLs."""
    sql_injection_patterns = [
        r"' OR '1'='1", r'--', r'; DROP TABLE', r'UNION SELECT', r'OR 1=1'
    ]
    suspicious_requests = logs[logs['URL'].str.contains('|'.join(sql_injection_patterns), na=False)]
    return suspicious_requests['IP'].unique().tolist()

def plot_top_ips(logs):
    top_ips = Counter(logs['IP']).most_common(10)
    ip_addresses, counts = zip(*top_ips)
    plt.bar(ip_addresses, counts)
    plt.xticks(rotation=45)
    plt.title('Top 10 IPs by Access Frequency')
    plt.ylabel('Number of Requests')
    plt.xlabel('IP Address')
    plt.tight_layout()

    plt.savefig('top_ips_plot.png')
    print("Plot saved as 'top_ips_plot.png'.")
    plt.close()  # Close the plot to free up memory

def export_results(data, file_name):
    """Export results to CSV and JSON formats."""
    if isinstance(data, list):
        # For list of IPs
        pd.DataFrame(data, columns=["IP"]).to_csv(f"{file_name}.csv", index=False)
        with open(f"{file_name}.json", "w") as json_file:
            json.dump(data, json_file, indent=4)
    elif isinstance(data, pd.DataFrame):
        # For pandas DataFrame
        data.to_csv(f"{file_name}.csv", index=False)
        data.to_json(f"{file_name}.json", orient="records", indent=4)

def geolocate_ips(ip_addresses):
    """Perform geolocation on the IPs."""
    geolocation_data = []

    for ip in ip_addresses:
        try:
            response = requests.get(f"http://ipinfo.io/{ip}/json?token={api_key}")
            data = response.json()
            geolocation_data.append({
                'IP': ip,
                'Country': data.get('country', 'N/A'),
                'Region': data.get('region', 'N/A'),
                'City': data.get('city', 'N/A'),
                'Location': data.get('loc', 'N/A')
            })
            time.sleep(1)  # To avoid hitting the API rate limits
        except Exception as e:
            print(f"Error geolocating {ip}: {e}")
            geolocation_data.append({'IP': ip, 'Country': 'N/A', 'Region': 'N/A', 'City': 'N/A', 'Location': 'N/A'})

    return geolocation_data

if __name__ == "__main__":
    log_file = "Apache.log"  # Replace with your log file path
    log_type = "apache"  # Change to "nginx" for Nginx logs, or "common" for common log format

    logs_df = parse_logs(log_file, log_type)
    print("Parsed Logs:\n", logs_df.head())

    # Detect brute force attempts
    brute_force_ips = detect_brute_force(logs_df)
    print("Potential Brute Force IPs:", brute_force_ips)
    export_results(brute_force_ips, "brute_force_ips")

    # Detect frequent 404 errors
    frequent_404_ips = detect_frequent_404s(logs_df)
    print("Frequent 404 Error IPs:", frequent_404_ips)
    export_results(frequent_404_ips, "frequent_404_ips")

    # Detect SQL injection attempts
    sql_injection_ips = detect_sql_injections(logs_df)
    print("Potential SQL Injection IPs:", sql_injection_ips)
    export_results(sql_injection_ips, "sql_injection_ips")

    # Geolocate IPs
    geolocation_data = geolocate_ips(brute_force_ips + frequent_404_ips + sql_injection_ips)
    export_results(geolocation_data, "geolocation_data")

    # Plot top 10 IPs
    plot_top_ips(logs_df)
