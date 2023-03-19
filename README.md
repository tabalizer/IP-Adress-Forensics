IP Analysis Script<br>
This Python script performs an analysis of a given IP address, including Whois, DNS, and geolocation analysis. The results are saved in both text and HTML formats, with an embedded map showing the geolocation in the HTML report. An audit log is also maintained for each analysis.

Features
Whois analysis
DNS analysis
Geolocation analysis
Text report generation
HTML report generation with embedded map
Audit log maintenance

Installation
Clone the repository or download the ip_analysis.py script.

Install the required Python libraries using the following command:

bash
Copy code
pip install -r requirements.txt

The required libraries are:
- ipwhois
- dnspython
- geoip2
- folium

Download the GeoLite2-City.mmdb file from MaxMind and extract it to a directory of your choice. You will be prompted for the path to this file when running the script.

Usage
Run the script using the following command:
bash
Copy code
python ip_analysis.py

Follow the prompts to enter the IP address, investigator's name, case number, and path to the GeoLite2-City.mmdb file.

The script will perform the analysis and display the results on the console.

The script will save the analysis results in two files:

ip_analysis_report.txt: A text report containing the analysis results.
ip_analysis_report.html: An HTML report containing the analysis results and an embedded map showing the geolocation of the IP address.
An audit log is maintained in the audit_log.json file, which contains the details of each analysis performed using the script.
