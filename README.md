Log Parser & Analyzer
A Python-based log parsing and analysis tool designed to work with various types of server logs (e.g., Apache, Nginx). This project can parse logs, detect anomalies, generate visualizations, and export analysis results. The tool is flexible, extendable, and equipped to handle API integrations for enhanced functionality.

Features
Log Parsing

Supports both Apache and Nginx log formats.
Handles incomplete or unmatched lines gracefully.
Allows dynamic extension for other log formats.
Threat Detection

Detect brute-force attempts based on repeated failed login attempts (401 status).
Identify frequent 404 errors.
Detect potential SQL injection attempts in URL queries.
Data Visualization

Generates a bar chart for the top 10 IPs by access frequency.
Saves plots as .png files for offline analysis.
API Integration

Calls an external GeoIP API to enrich log data with geolocation information (e.g., country, region).
Sensitive API keys are stored securely in .env files.
Export Results

Outputs analysis to .csv and .json formats for further processing.
Customizable Settings

Thresholds for detecting brute-force and frequent errors can be modified.
Regex patterns are extendable for other log formats.
Requirements
Install dependencies using the following command:

bash
Copy code
pip install -r requirements.txt
Dependencies
pandas: For structured log data storage and manipulation.
matplotlib: For visualizing access patterns.
requests: For making API calls to GeoIP services.
python-dotenv: For managing environment variables.
Installation and Usage
Step 1: Clone the Repository
bash
Copy code
git clone https://github.com/jimmymugo/log-parser.git
cd log-parser
Step 2: Set Up Environment Variables
Create a .env file in the root directory:
bash
Copy code
touch .env
Add your API key for GeoIP services:
makefile
Copy code
API_KEY=your_api_key_here
Step 3: Run the Script
bash
Copy code
python log_parser.py
Step 4: Outputs
CSV/JSON Files: Analysis results are saved in the working directory.
Plots: Saved as top_ips_plot.png.
Example Usage
Detecting Brute Force Attempts
The tool identifies IP addresses with excessive failed login attempts:

bash
Copy code
python log_parser.py
Detecting SQL Injections
The script scans for suspicious URLs containing SQL injection patterns and outputs the flagged IPs.

Geolocation of IPs
Use GeoIP API integration to add country and region details to the parsed log data.

Configuration
Adjust Thresholds
Modify the thresholds for brute force or frequent 404 detections in the script:
python
Copy code
def detect_brute_force(logs, threshold=10):
    ...
def detect_frequent_404s(logs, threshold=20):
    ...
Extend Regex Patterns
Add or modify patterns for new log formats in the parse_logs function.
Contributing
Contributions are welcome! Please fork the repository and submit a pull request.
Ensure your code adheres to the project's coding standards and includes appropriate documentation.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Author
Developed by jimmymugo.
