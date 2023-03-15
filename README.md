# IP-Adress-Forensics
A small python script that will do some queries helping investigate IP-addresses with focus on extracting DNS, WHOIS, Requests, ipWhois information for a certain IP adress

To run the script, you will need to have Python 3 installed on your computer. Additionally, you will need to install the following Python modules:

socket: This module provides a way to look up DNS information for an IP address.
whois: This module provides a way to look up WHOIS information for an IP address.
requests: This module provides a way to make HTTP requests to external APIs, which we will use to perform geolocation lookups.
ipwhois: This module provides a way to look up IP information, including RDAP information, for an IP address.
You can install these modules using pip, the Python package manager. Open a command prompt or terminal window, and type the following commands:

Requirements:

****
perl
Copy code
pip install socket
pip install python-whois
pip install requests
pip install ipwhois
****

When you run this script, it prompts you to enter an IP address to investigate. It then performs a DNS lookup, WHOIS lookup, geolocation lookup, and IP information lookup on the specified IP address, and prints the results to the console.

Note that the ipwhois module requires an API key to perform RDAP lookups. If you don't have an API key, you can sign up for a free one at https://whoisxmlapi.com/. Once you have an API key, you can pass it to the IPWhois constructor like this:

****
python
Copy code
from ipwhois import IPWhois

api_key = "YOUR_API_KEY"
ipwhois_result = IPWhois(ip_address, api_key=api_key).lookup_rdap()
****

This will allow you to perform RDAP lookups using the ipwhois module.

RUN THE SCRIPT and you will be prompted for an IP-address

\\python ip_investigation.py