import socket
import whois
import requests
from ipwhois import IPWhois

def get_dns(ip_address):
    try:
        dns_result = socket.gethostbyaddr(ip_address)
        return dns_result[0]
    except socket.herror:
        return None

def get_whois(ip_address):
    try:
        w = whois.whois(ip_address)
        return w.text
    except whois.parser.WhoisError:
        return None

def get_geolocation(ip_address):
    try:
        url = f"https://ipinfo.io/{ip_address}/json"
        response = requests.get(url)
        data = response.json()
        return f"{data['city']}, {data['region']}, {data['country']}"
    except:
        return None

def get_ip_info(ip_address):
    ipwhois_result = IPWhois(ip_address).lookup_rdap()
    return ipwhois_result

if __name__ == "__main__":
    ip_address = input("Enter an IP address to investigate: ")

    print("Performing DNS lookup...")
    dns_result = get_dns(ip_address)
    if dns_result is not None:
        print("DNS result:", dns_result)
    else:
        print("DNS lookup failed.")

    print("\nPerforming WHOIS lookup...")
    whois_result = get_whois(ip_address)
    if whois_result is not None:
        print("WHOIS result:\n", whois_result)
    else:
        print("WHOIS lookup failed.")

    print("\nPerforming geolocation lookup...")
    geolocation_result = get_geolocation(ip_address)
    if geolocation_result is not None:
        print("Geolocation result:", geolocation_result)
    else:
        print("Geolocation lookup failed.")

    print("\nPerforming IP information lookup...")
    ip_info = get_ip_info(ip_address)
    if ip_info is not None:
        print("IP information:\n", ip_info)
    else:
        print("IP information lookup failed.")
