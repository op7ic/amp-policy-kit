# amp-policy-kit

This repository contains scripts designed to help in policy assessment of existing Cisco AMP installation in either cloud or on-prem mode.

## Prerequisites 

Install the following prerequsites:

* Python3
* [xmltodict](https://pypi.org/project/xmltodict/)
* [beautifulsoup4](https://pypi.org/project/beautifulsoup4/)

The following command line should take care of prerequisites on Debian/Ubuntu/WSL:
```
pip3 install xmltodict beautifulsoup4
```

## download-policy-xml.py

This script dumps all existing policies from AMP console in XML format to specified folder. Please edit [config.txt](config.txt) and add appropriate API keys.

Usage:
```
usage: download-policy-xml.py [-h] -c FILE -o OUTOUT_FOLDER

optional arguments:
  -h, --help            show this help message and exit
  -c FILE, --config FILE
                        path to config file
  -o OUTOUT_FOLDER, --output OUTOUT_FOLDER
                        path to output folder
```

How to invoke:
```
python3 download-policy-xml.py --config /tmp/config.txt --output /tmp/localpolicy
```

## online-policy-audit.py

This script will perform an online audit on all existing policies from AMP console and highlight specific security concerns such as: 

- Presence of "*" in exclusion list
- Disabled security engine such as 'tetra' or 'spero'
- "Audit" mode enabled on some security settings
- Lack of "deep" scanning for archives, processes or other file types such as email
- Long TTL for hash checks
- Disabled Network Flow Monitoring (NFM)
- Policy not updated for 12 or more months 
- AMP installation not protected by password

Please edit [config.txt](config.txt) and add appropriate API keys.

Usage:
```
usage: online-policy-audit.py [-h] -c FILE

optional arguments:
  -h, --help            show this help message and exit
  -c FILE, --config FILE
                        path to config file
```

How to invoke:
```
python3 online-policy-audit.py --config /tmp/config.txt
```

## offline-policy-audit.py

This script will perform an offline audit of an XML policy file passed in as argument and higlight the same defficienices as 'online' mode.

Usage:
```
usage: offline-policy-audit.py [-h] -i FILE

optional arguments:
  -h, --help            show this help message and exit
  -i FILE, --input FILE
                        path to AMP XML config file
```

How to invoke:
```
python3 offline-policy-audit.py -i policyfile.xml
```

## AMP4E API Endpoints 

AMP API endpoint need to be specified in the config file under 'domainIP' parameter. Please choose one depending on location of your console:

- ```api.eu.amp.cisco.com``` - AMP EU 
- ```api.amp.cisco.com``` - AMP
- ```api.apjc.amp.cisco.com``` - AMP APJC

## Example output from auditor

```
[+] Policy Name: Domain Controller
[+] Policy GUID: XXXXXXXXXX
[+] Policy Version: 129
[+] Business GUID: XXXXXXXXXX
[!] WARNING, Last policy change: 102 days, 8:58:49.211369 ago
[+] File Exclusions in policy:
         C:\Program Files\Sophos\AutoUpdate\Cache\
         C:\ProgramData\Sophos\
         C:\ProgramData\Sophos\AutoUpdate\Cache\
         C:\Quarantine\
         C:\System Volume Information\tracking.log
        WARNING, wildecard : ^[A-Za-z]:\\.*\.sas.*
        WARNING, wildecard : C:\\Users\\.*\\AppData\\Local\\Microsoft\\Office\\.*\\OfficeFileCache
        WARNING, wildecard : C:\\Users\\.*\\AppData\\Local\\Microsoft\\OneDrive\\
        WARNING, wildecard : C:\\Users\\.*\\OneDrive\\
        WARNING, wildecard : C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp\\Sophos.*
        WARNING, wildecard : C:\\Windows\\Temp\\Sophos.*
[+] Certificate Exclusions in policy:
         VeriSign Class 3 Code Signing
[+] Process Exclusions in policy:
         2|0||C:\Program Files\Altiris\Altiris Agent\AeXNSAgent.exe|1|
         2|0||C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe|1|
         2|0||C:\Program Files\McAfee\Endpoint Security\Adaptive Threat Protection\mfeatp.exe|1|
         2|0||C:\Program Files\McAfee\Endpoint Security\Endpoint Security Platform\mfeesp.exe|1|
         2|0||C:\Program Files\McAfee\Endpoint Security\Threat Prevention\mfetp.exe|1|
[+] Specific Policy Misconfiguration:
        [!]WARNING, System Isolation feature is disabled
        [!]WARNING, ORBITAL is disabled
        [!]WARNING, Monitoring of Network Drives is diabled
        [!]WARNING, Network Flow Monitoring is disabled
        [!]WARNING, Exploit Heuristic is disabled
```


## TODO

- [ ] Android policy handling
- [ ] iOS policy handling
- [x] Windows policy handling
- [x] Linux policy handling
- [x] Mac policy handling
- [x] Security configuration parsing
- [x] Policy download script
- [x] Policy parsing in online/offline modes