from ipwhois import IPWhois

api_key = "YOUR_API_KEY"
ipwhois_result = IPWhois(ip_address, api_key=api_key).lookup_rdap()
