import argparse
import os
import sys
import requests
import mimetypes
import validators
from dotenv import load_dotenv

load_dotenv()

virusTotalURL = "https://www.virustotal.com/api/v3"


def file_checker(file):
    mime = mimetypes.guess_type(file)
    if mime[0] != "text/plain":
        print("Please provide a text file (.txt)")
        sys.exit()

    try:
        with open(file, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        raise ValueError("File is not a valid UTF-8 text file.")
    except FileNotFoundError:
        raise ValueError("File not found.")

    if not content.strip():
        raise ValueError("File is empty.")

    entries = [item.strip() for item in content.replace('\n', ',').split(',') if item.strip()]
    if not entries:
        raise ValueError("File has no valid entries.")
    return entries


def ipinfo(ip, ipt):
    url_ipinfo = f"https://ipinfo.io/{ip}?token={ipt}"
    try:
        response = requests.get(url_ipinfo, headers={"accept": "application/json"}, timeout=5)
        response.raise_for_status()
        data = response.json()
        return {
            "ip": data.get("ip", "-"),
            "hostname": data.get("hostname", "-"),
            "city": data.get("city", "-"),
            "region": data.get("region", "-"),
            "country": data.get("country", "-"),
            "org": data.get("org", "-"),
            "loc": data.get("loc", "-"),
            "postal": data.get("postal", "-"),
            "timezone": data.get("timezone", "-")
        }
    except Exception as err:
        print(f"[IPInfo] Error fetching data for {ip}: {err}")
        return None


def ip_scan(ip, ipinfo_token, token):
    url = f"{virusTotalURL}/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": token}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", "-")
        suspicious = stats.get("suspicious", "-")
    except Exception as e:
        print(f"[VirusTotal] Error scanning IP {ip}: {e}")
        malicious = suspicious = "-"

    ipinfo_data = ipinfo(ip, ipinfo_token)
    print("=" * 60)
    print(f"Scanning IP: {ip}")
    print(f"Malicious: {malicious}, Suspicious: {suspicious}")

    if ipinfo_data:
        print(f"{ip}'s Info --> Hostname: {ipinfo_data['hostname']}, City: {ipinfo_data['city']}, "
              f"Region: {ipinfo_data['region']}, Country: {ipinfo_data['country']}, "
              f"Org: {ipinfo_data['org']}\n")


def url_scan(urlInput, token):
    url = f"{virusTotalURL}/urls"
    headers = {"accept": "application/json", "x-apikey": token}
    data = {"url": urlInput}
    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        json_data = response.json()
        url_to_analyze = json_data.get("data", {}).get("links", {}).get("self")
        if not url_to_analyze:
            print(f"Could not retrieve analysis link for {urlInput}")
            return

        response2 = requests.get(url_to_analyze, headers=headers, timeout=10)
        response2.raise_for_status()
        url_analysis_data = response2.json()
        stats = url_analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
        malicious = stats.get("malicious", "-")
        suspicious = stats.get("suspicious", "-")
    except Exception as e:
        print(f"[VirusTotal] Error scanning URL {urlInput}: {e}")
        malicious = suspicious = "-"

    print("=" * 60)
    print(f"Scanning URL: {urlInput}")
    print(f"Malicious: {malicious}, Suspicious: {suspicious}\n")


def main():
    parser = argparse.ArgumentParser(description="Scan IPs and URLs using VirusTotal and IPInfo APIs.")
    parser.add_argument('-fip', '--fip', help="File with IP addresses")
    parser.add_argument('-fu', '--furl', help="File with URLs")
    parser.add_argument('-ip', '--ip', help="Single IP address")
    parser.add_argument('-u', '--url', help="Single URL")
    parser.add_argument('-t', '--token', help="VirusTotal API Token")
    parser.add_argument('-ipt', '--ipinfo', help="IPInfo Token")

    args = parser.parse_args()

    token = args.token or os.getenv("VT_API_KEY")
    ipinfo_token = args.ipinfo or os.getenv("IPINFO_TOKEN")

    if not token:
        print("Error: VirusTotal token not provided. Use --token or set VT_API_KEY.")
        sys.exit(1)
    if not ipinfo_token:
        print("Error: IPInfo token not provided. Use --ipinfo or set IPINFO_TOKEN.")
        sys.exit(1)

    # Process single IP
    if args.ip:
        if validators.ipv4(args.ip) or validators.ipv6(args.ip):
            ip_scan(args.ip, ipinfo_token, token)
        else:
            print("Invalid IP address.")

    # Process single URL
    if args.url:
        if validators.url(args.url):
            url_scan(args.url, token)
        else:
            print("Invalid URL.")

    # Process multiple URLs from file
    if args.furl:
        try:
            urls = file_checker(args.furl)
            for url in urls:
                if validators.url(url):
                    url_scan(url, token)
                else:
                    print(f"Invalid URL: {url}")
        except Exception as e:
            print(f"Error reading URL file: {e}")

    # Process multiple IPs from file
    if args.fip:
        try:
            ips = file_checker(args.fip)
            for ip in ips:
                if validators.ipv4(ip) or validators.ipv6(ip):
                    ip_scan(ip, ipinfo_token, token)
                else:
                    print(f"Invalid IP: {ip}")
        except Exception as e:
            print(f"Error reading IP file: {e}")


if __name__ == "__main__":
    main()
