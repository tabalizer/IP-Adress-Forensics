import folium
import json
import os
from datetime import datetime
from ipwhois import IPWhois
import dns.resolver
import geoip2.database

AUDIT_LOG_FILE = "audit_log.json"
REPORT_FILE = "ip_analysis_report.txt"

def save_audit_log(log_data):
    if os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, "r") as f:
            logs = json.load(f)
    else:
        logs = []

    logs.append(log_data)

    with open(AUDIT_LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

def whois_analysis(ip):
    whois = IPWhois(ip)
    raw_result = whois.lookup_rdap()
    
    result = {
        "ip_address": raw_result.get("network", {}).get("ip_address"),
        "cidr": raw_result.get("network", {}).get("cidr"),
        "asn": raw_result.get("asn"),
        "asn_description": raw_result.get("asn_description"),
        "country": raw_result.get("asn_country_code"),
        "registrar": raw_result.get("registrar"),
        "registration_date": raw_result.get("registration_date"),
        "last_updated": raw_result.get("last_updated")
    }
    return result

def dns_analysis(ip):
    resolver = dns.resolver.Resolver()
    reverse_ip = dns.reversename.from_address(ip)
    result = resolver.resolve(reverse_ip, "PTR")
    return result[0].to_text()

def geolocation_analysis(ip, database_path):
    with geoip2.database.Reader(database_path) as reader:
        result = reader.city(ip)
    return {
        "country_iso_code": result.country.iso_code,
        "country_name": result.country.name,
        "city_name": result.city.name,
        "postal_code": result.postal.code,
        "latitude": result.location.latitude,
        "longitude": result.location.longitude,
        "time_zone": result.location.time_zone
    }

def save_report(report_data, file_path):
    with open(file_path, "w") as f:
        f.write(report_data)

def create_report(audit_log_data):
    report = "Investigator: {}\n".format(audit_log_data["investigator"])
    report += "Case Number: {}\n".format(audit_log_data["case_number"])
    report += "Timestamp: {}\n".format(audit_log_data["timestamp"])
    report += "IP Address: {}\n\n".format(audit_log_data["ip_address"])

    report += "Whois Analysis:\n"
    report += json.dumps(audit_log_data["whois_data"], indent=4)
    report += "\n\n"

    report += "DNS Analysis:\n"
    report += audit_log_data["dns_data"]
    report += "\n\n"

    report += "Geolocation Analysis:\n"
    report += json.dumps(audit_log_data["geolocation_data"], indent=4)
    report += "\n\n"

    lat = audit_log_data["geolocation_data"]["latitude"]
    lon = audit_log_data["geolocation_data"]["longitude"]
    report += "Google Maps Link:\n"
    report += f"https://www.google.com/maps?q={lat},{lon}"

    return report
    
def create_map(latitude, longitude):
    map = folium.Map(location=[latitude, longitude], zoom_start=13)
    folium.Marker([latitude, longitude]).add_to(map)
    return map.get_root().render()
    
def create_html_report(audit_log_data, map_html):
    report = f"""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>IP Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        h1, h2 {{ margin-bottom: 0.5em; }}
        pre {{ white-space: pre-wrap; }}
    </style>
</head>
<body>
    <h1>IP Analysis Report</h1>
    <h2>Investigator: {audit_log_data["investigator"]}</h2>
    <h2>Case Number: {audit_log_data["case_number"]}</h2>
    <h2>Timestamp: {audit_log_data["timestamp"]}</h2>
    <h2>IP Address: {audit_log_data["ip_address"]}</h2>

    <h2>Whois Analysis:</h2>
    <pre>{json.dumps(audit_log_data["whois_data"], indent=4)}</pre>

    <h2>DNS Analysis:</h2>
    <pre>{audit_log_data["dns_data"]}</pre>

    <h2>Geolocation Analysis:</h2>
    <pre>{json.dumps(audit_log_data["geolocation_data"], indent=4)}</pre>

    <h2>Geolocation Map:</h2>
    {map_html}
</body>
</html>
"""
    return report

def main():
    ip = input("Enter the IP address: ")
    investigator = input("Enter the investigator's name: ")
    case_number = input("Enter the case number: ")
    database_path = input("Enter the path to the GeoLite2-City.mmdb file: ")

    print("\nPerforming Whois analysis...")
    whois_data = whois_analysis(ip)
    for key, value in whois_data.items():
        if value:
            print(f"{key.capitalize().replace('_', ' ')}: {value}")

    print("\nPerforming DNS analysis...")
    dns_data = dns_analysis(ip)
    print(dns_data)

    print("\nPerforming geolocation analysis...")
    geolocation_data = geolocation_analysis(ip, database_path)
    print(json.dumps(geolocation_data, indent=4))

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    audit_log_data = {
        "investigator": investigator,
        "case_number": case_number,
        "timestamp": timestamp,
        "ip_address": ip,
        "whois_data": whois_data,
        "dns_data": dns_data,
        "geolocation_data": geolocation_data
    }
    save_audit_log(audit_log_data)

    print("\nSaving the text report...")
    text_report = create_report(audit_log_data)
    save_report(text_report, REPORT_FILE)
    print(f"Text report saved to {REPORT_FILE}")

    print("\nSaving the HTML report...")
    lat = audit_log_data["geolocation_data"]["latitude"]
    lon = audit_log_data["geolocation_data"]["longitude"]
    map_html = create_map(lat, lon)
    html_report = create_html_report(audit_log_data, map_html)
    save_report(html_report, "ip_analysis_report.html")
    print("HTML report saved to ip_analysis_report.html")

if __name__ == "__main__":
    main()
