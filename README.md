# IP Analysis Report

A Python script that generates an IP address analysis report containing Whois, DNS, and geolocation information.

## Prerequisites

- Python 3.6 or later
- The following Python libraries:
  - folium
  - ipwhois
  - dnspython
  - geoip2

## Installation

	1. Install Python from the [official website](https://www.python.org/downloads/) if you haven't already.
	2. Clone the repository or download the script files.
	3. Install the required Python libraries using pip by running the following command in your terminal or command prompt:

	"pip install folium ipwhois dnspython geoip2"

Usage

	1. 	Download the GeoLite2-City.mmdb database file from MaxMind's website. Place the file in the same folder as the script.
	2. 	Open a terminal or command prompt, navigate to the directory containing the script, and run the script using the following command:

	"python ip_analysis.py"

	3. 	Follow the prompts to enter the IP address, investigator's name, and case number.
	4. 	The script will generate an IP address analysis report containing Whois, DNS, and geolocation information. 
		The report will be saved as a text file (ip_analysis_report.txt) and an HTML file (ip_analysis_report.html) in the same folder as the script.
	5. The script will also save the analysis data to an audit log CSV file (audit_log.csv).

License
This project is licensed under the MIT License - see the LICENSE file for details.

Disclaimer
The data provided by this script is for informational purposes only and should not be considered as legal advice. 
The accuracy of the data is not guaranteed, and the use of the information provided is at your own risk. 
Always consult with a legal professional before taking any action based on the information provided.
