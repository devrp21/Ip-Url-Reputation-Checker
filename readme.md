
# 🛡️ IP & URL Reputation Checker

A powerful and lightweight Python CLI tool to analyze IP addresses and URLs using **VirusTotal** and **IPInfo** APIs.

---


## 🚀 Features

- 🔍 Check the reputation of IP addresses and URLs
- 📄 Input from plain text files or single entries via CLI
- 🧠 Uses VirusTotal for threat detection
- 🌍 Uses IPInfo for location and ISP data
- ✅ Graceful error handling and input validation
- 🔐 API keys via environment or CLI options

---

## 📥 Installation

1. **Clone the repository**:

```bash
git clone https://github.com/devrp21/Ip-Url-Reputation-Checker.git
cd ip-url-reputation-checker
````

2. **Install dependencies**:

```bash
pip install -r requirements.txt
```

3. **Set up environment variables**:

Create a `.env` file manually or copy the example:

```bash
cp .env.example .env
```

Edit `.env` and insert your keys:

```
VT_API_KEY=your_virustotal_api_key
IPINFO_TOKEN=your_ipinfo_token
```

---

## 🧪 Usage

Run the script with:

```bash
python main.py [options]
```

---

### 🔧 CLI Options

| Option     | Description                         | Example                     |
| ---------- | ----------------------------------- | --------------------------- |
| `--ip`     | Scan a single IP                    | `--ip 8.8.8.8`              |
| `--url`    | Scan a single URL                   | `--url https://example.com` |
| `--fip`    | File with multiple IPs              | `--fip ips.txt`             |
| `--furl`   | File with multiple URLs             | `--furl urls.txt`           |
| `--token`  | VirusTotal API key (overrides .env) | `--token ABC123...`         |
| `--ipinfo` | IPInfo token (overrides .env)       | `--ipinfo XYZ456...`        |

---

## 📂 Example Files

### `ips.txt`

```
8.8.8.8
1.1.1.1
```

### `urls.txt`

```
https://example.com
http://suspicious-site.com
```

---

## 🧾 Example Commands

### Scan a single IP:

```bash
python main.py --ip 8.8.8.8
```

### Scan a single URL:

```bash
python main.py --url https://example.com
```

### Scan from file of IPs:

```bash
python main.py --fip ips.txt
```

### Scan from file of URLs:

```bash
python main.py --furl urls.txt
```

### Use API keys directly (instead of .env):

```bash
python main.py --ip 1.1.1.1 --token YOUR_VT_KEY --ipinfo YOUR_IPINFO_KEY
```

---

## 🔐 Get Your API Keys

* 🔗 [Get a free VirusTotal API key](https://www.virustotal.com/gui/join-us)
* 🔗 [Get a free IPInfo API token](https://ipinfo.io/signup)

> Both services offer free tiers with generous limits.

---

## ✅ Sample Output

```
============================================================
Scanning IP: 8.8.8.8
IP : 8.8.8.8, Malicious Detection : 0, Suspicious Detection : 0
8.8.8.8's IP Reputation --> Hostname : dns.google, City : Mountain View, Region : California, Country : US, Organization : Google LLC
============================================================
Scanning URL: https://example.com
URL : https://example.com, Malicious Detection : 0, Suspicious Detection : 0
```

---

## 📁 .env.example

```env
# Environment variable template

VT_API_KEY=your_virustotal_api_key
IPINFO_TOKEN=your_ipinfo_token
```


## 🙌 Contributing

Pull requests and issues are welcome. If you'd like to contribute, fork the repo and submit a PR.

---

## 🔗 Developer Resources

* 📘 [VirusTotal API Docs](https://docs.virustotal.com/)
* 📘 [IPInfo API Docs](https://ipinfo.io/developers)

