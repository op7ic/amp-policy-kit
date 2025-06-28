# Cisco Secure Endpoint Policy Kit

This repository contains comprehensive scripts for security assessment of Cisco Secure Endpoint (formerly AMP for Endpoints) policies in both cloud and on-premises deployments.

## Prerequisites 

```bash
pip3 install xmltodict beautifulsoup4 requests
```

**Supported Python Versions:** 3.6+   
**Supported API Versions:** v1, v0

## 📊 Available Scripts

### Features

- **Per-Policy HTML Reports** with visual severity indicators
- **Multiple Output Formats** (JSON, HTML, CSV)
- **Parallel Processing** for faster auditing
- **Bulk Policy Downloads** for comprehensive analysis
- **Automatic File Organization** by policy type
- **API Rate Limiting** handling
- **Error Recovery** and retry logic

### 🔍 Comprehensive Auditing (Recommended)

#### `online-policy-audit.py`
**Advanced online policy auditing with detailed per-policy reports**

```bash
python3 online-policy-audit.py -c config.txt -o audit_results/
python3 online-policy-audit.py -c config.txt -o audit_results/ --formats json html csv
```
#### `offline-policy-audit.py`
**Comprehensive offline analysis of individual policy files**

```bash
# Console output only
python3 offline-policy-audit.py -i policy.xml

# Generate detailed reports
python3 offline-policy-audit.py -i policy.xml -o reports/ --formats html json csv

# iOS plist support
python3 offline-policy-audit.py -i ios_policy.plist -o reports/ --formats html
```

#### `download-policy-xml.py`
**Policy downloader for bulk analysis**

```bash
python3 download-policy-xml.py -c config.txt -o policies/
python3 download-policy-xml.py -c config.txt -o policies/ --parallel
```
## ⚙️ Configuration

Create a `config.txt` file with your API credentials:

```ini
[api]
client_id = your_client_id_here
api_key = your_api_key_here
domainIP = api.amp.cisco.com
```

### 🌍 Available API Endpoints

Choose the appropriate endpoint for your region:

| Region | Endpoint | Description |
|--------|----------|-------------|
| **Americas** | `api.amp.cisco.com` | North/South America |
| **Europe** | `api.eu.amp.cisco.com` | Europe, Middle East, Africa |
| **Asia-Pacific** | `api.apjc.amp.cisco.com` | Asia-Pacific region |

### 🔑 Getting API Credentials

1. Log in to your Cisco Secure Endpoint Console
2. Navigate to **Accounts > Organization Settings**
3. Click **Configure API Credentials** under Features
4. Generate a new **Client ID** and **API Key**

## 🛡️ Comprehensive Security Checks

### 🔴 Critical Issues
- **Dangerous Wildcards in Exclusions** - `*`, `.*`, `**` patterns
- **Missing Password Protection** - Installation not secured
- **Behavioral Protection Disabled** - Advanced analytics off
- **Policy Outdated** - Not updated over 1 year
- **Exploit Prevention Disabled** - Core protection features off

### 🟡 Warnings  
- **Audit-Only Security Modes** - Detection without blocking
- **Disabled Security Engines** - TETRA, SPERO, ETHOS off
- **No Scheduled Scans Configured** - Missing proactive scanning
- **Infrequent Scheduled Scans** - Monthly or less frequent scanning

### 🔵 Informational
- **Long Cache TTLs** - Extended lookup times
- **Disabled Telemetry** - Reduced threat intelligence
- **UI Security Settings** - User interface exposure
- **Update Configuration** - Update window restrictions

### 📋 Supported Categories
- **Exploit Prevention** 
- **Behavioral Analytics**
- **Script Protection (AMSI)**
- **Network Monitoring** (including NFM action level validation)
- **File/Process Exclusions** (enhanced wildcard detection)
- **Scheduled Scanning** (frequency analysis and compliance)
- **Password Protection** (installation security)
- **Telemetry & Privacy**
- **Command Line Capture**
- **Endpoint Isolation**
- **Scanning Engines**
- **User Interface Security**

## 📈 Sample Output

### Console Output (Comprehensive Mode)
```
================================================================================
CISCO SECURE ENDPOINT COMPREHENSIVE POLICY AUDIT
================================================================================

[+] Policy Name: Protect
[+] Policy Type: WINDOWS
[+] Policy UUID: xxxxxx-xxxxx-xxxxx-xxxx
[+] Serial Number: 508
[+] Last Updated: 2025-06-04 23:08:04+00:00 (22 days ago)

[+] Comprehensive Exclusion Analysis:
  File Exclusions Analysis:
    [!] DANGEROUS: C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp\\Sophos.*
    [!] DANGEROUS: CSIDL_WINDOWS\\Security\\database\\.*\.edb
  
  Process Exclusions Analysis:
    [!] 2|0||C:\Windows\WinSxS\*\TiWorker.exe|1|

[+] Comprehensive Agent Security Analysis:

================================================================================
COMPREHENSIVE AUDIT SUMMARY
================================================================================

[!] CRITICAL ISSUES (7):
  - Dangerous Wildcard in File Exclusion: Exclusion contains risky pattern

[*] WARNINGS (16):
  - Behavioral Protection in Audit Mode: Detection only, not blocking
  - SSL Host Verification Disabled: Insecure connections allowed
  - No Scheduled Scans Configured: Missing proactive scanning

[i] INFORMATIONAL (12):
  - Many User Notifications Enabled: 5 notification types visible

```

### Output Formats
| Format | Use Case | Features |
|--------|----------|----------|
| **Console** | Quick analysis | Real-time colored output |
| **HTML** | Executive reports | Visual charts, professional styling |
| **JSON** | Automation/SIEM | Machine-readable, API integration |
| **CSV** | Spreadsheet analysis | Excel/Google Sheets compatible |

## 📚 Documentation

- **[Cisco Secure Endpoint Documentation](https://docs.amp.cisco.com/)**
- **[API Reference](https://developer.cisco.com/docs/secure-endpoint/)**
- **[Policy Configuration Guide](https://www.cisco.com/c/en/us/support/security/amp-endpoints/products-tech-notes-list.html)**

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📄 License

See [LICENSE](LICENSE) file for details.

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.