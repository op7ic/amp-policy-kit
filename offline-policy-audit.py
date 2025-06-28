#!/usr/bin/env python3
"""
Cisco Secure Endpoint Policy Auditor - Comprehensive Offline Mode
Performs comprehensive security audit on Cisco Secure Endpoint XML/plist policy files

Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file in this repository
GitHub: https://github.com/op7ic/amp-policy-kit
"""

import sys
import argparse
import os
import json
import datetime
from typing import Dict, Any, Optional, List
from urllib.parse import unquote
from xml.etree.ElementTree import fromstring, ElementTree, tostring
from pathlib import Path
import logging
import csv

try:
    import xmltodict
    from bs4 import BeautifulSoup
    import plistlib
except ImportError:
    print("[!] Missing required dependencies")
    print("[!] Please install: pip3 install xmltodict beautifulsoup4")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class ComprehensivePolicyAuditor:
    """Comprehensive auditor for Cisco Secure Endpoint policies"""
    
    def __init__(self, policy_path: str, output_dir: str = None, formats: List[str] = None):
        self.policy_path = Path(policy_path)
        self.output_dir = Path(output_dir) if output_dir else None
        self.policy_type = None
        self.policy_data = None
        self.findings = []
        self.formats = formats or ['console']
        
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def load_policy(self) -> bool:
        """Load and parse the policy file"""
        try:
            content = self.policy_path.read_text()
            
            # Check if it's an iOS plist file
            if content.startswith('<?xml') and 'plist' in content[:200]:
                self._parse_ios_policy(content)
                return True
                
            # Parse as regular XML
            tree = ElementTree(fromstring(content))
            root = tree.getroot()
            
            # Convert to dictionary for easier access
            soup = BeautifulSoup(tostring(root), "xml")
            self.policy_data = xmltodict.parse(soup.prettify(), dict_constructor=dict)
            
            # Detect policy type
            self._detect_policy_type()
            return True
            
        except Exception as e:
            logger.error(f"Failed to load policy: {e}")
            return False
    
    def _parse_ios_policy(self, content: str):
        """Parse iOS plist format policies"""
        try:
            plist_data = plistlib.loads(content.encode())
            self.policy_type = 'ios'
            self.policy_data = {'ios_plist': plist_data}
            logger.info("Detected iOS policy in plist format")
        except Exception as e:
            logger.error(f"Failed to parse iOS plist: {e}")
            raise
    
    def _detect_policy_type(self):
        """Detect the platform type from policy content"""
        try:
            json_str = json.dumps(self.policy_data)
            
            if "Spotlight" in json_str or "/Library/" in json_str:
                self.policy_type = "mac"
            elif "CSIDL_WINDOWS" in json_str or "C:\\" in json_str:
                self.policy_type = "windows"
            elif "/opt/" in json_str or "/var/" in json_str:
                self.policy_type = "linux"
            elif "android" in json_str.lower():
                self.policy_type = "android"
            else:
                self.policy_type = "network"
                
            logger.info(f"Detected policy type: {self.policy_type}")
            
        except Exception as e:
            logger.warning(f"Could not detect policy type: {e}")
            self.policy_type = "unknown"
    
    def audit(self):
        """Perform comprehensive security audit"""
        if not self.policy_data:
            logger.error("No policy data loaded")
            return
            
        if 'console' in self.formats:
            print("\n" + "="*80)
            print("CISCO SECURE ENDPOINT COMPREHENSIVE POLICY AUDIT")
            print("="*80 + "\n")
        
        if self.policy_type == 'ios':
            self._audit_ios_policy()
        else:
            self._audit_standard_policy()
            
        if 'console' in self.formats:
            self._print_summary()
        
        # Generate reports if output directory is specified
        if self.output_dir:
            self._generate_reports()
    
    def _audit_ios_policy(self):
        """Comprehensive iOS policy audit"""
        plist = self.policy_data['ios_plist']
        
        if 'console' in self.formats:
            print("[+] iOS Policy Analysis")
            print(f"[+] Display Name: {plist.get('PayloadDisplayName', 'Unknown')}")
            print(f"[+] Identifier: {plist.get('PayloadIdentifier', 'Unknown')}")
            print(f"[+] Organization: {plist.get('PayloadOrganization', 'Unknown')}")
        
        # Comprehensive iOS checks
        if 'PayloadContent' in plist:
            for content in plist['PayloadContent']:
                if 'VendorConfig' in content:
                    vendor_cfg = content['VendorConfig']
                    
                    if vendor_cfg.get('enabled') == 'false':
                        self.findings.append(self._create_finding(
                            "CRITICAL", "iOS Protection Disabled",
                            "iOS Secure Endpoint protection is disabled",
                            "Enable iOS protection in vendor configuration",
                            "iOS Security"
                        ))
                    
                    if 'scan_on_demand' in vendor_cfg and vendor_cfg['scan_on_demand'] == 'false':
                        self.findings.append(self._create_finding(
                            "WARNING", "On-Demand Scanning Disabled",
                            "On-demand scanning capability is disabled",
                            "Enable on-demand scanning for manual threat detection",
                            "iOS Security"
                        ))
    
    def _audit_standard_policy(self):
        """Comprehensive audit of standard XML policies"""
        # Parse header information
        self._parse_header()
        
        # Get config root
        config = self._get_nested_value(['ns0:Signature', 'ns0:Object', 'ns0:config'])
        if not config:
            self.findings.append(self._create_finding(
                "CRITICAL", "Invalid Policy Structure",
                "Policy XML structure is invalid or corrupted",
                "Verify policy file integrity",
                "Policy Structure"
            ))
            return
        
        # Comprehensive audits
        self._audit_exclusions_comprehensive(config.get('ns0:exclusions', {}))
        self._audit_agent_comprehensive(config.get('ns0:agent', {}))
        self._audit_connection_security(config)
        self._audit_update_security(config)
        self._audit_ui_security(config)
        self._audit_orbital_security(config.get('ns0:orbital', {}))
    
    def _create_finding(self, severity: str, title: str, description: str, 
                       recommendation: str = "", category: str = "General") -> Dict[str, Any]:
        """Create a standardized finding"""
        return {
            'severity': severity,
            'title': title,
            'description': description,
            'recommendation': recommendation,
            'category': category,
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    def _parse_header(self):
        """Parse and display policy header with comprehensive checks"""
        try:
            header = self._get_nested_value(['ns0:Signature', 'ns0:Object', 'ns0:config', 'ns0:janus'])
            if not header:
                return
                
            policy = header.get('ns0:policy', {})
            business = header.get('ns0:business', {})
            
            if 'console' in self.formats:
                print(f"[+] Policy Name: {policy.get('ns0:name', 'Unknown')}")
                print(f"[+] Policy Type: {self.policy_type.upper()}")
                print(f"[+] Policy UUID: {policy.get('ns0:uuid', 'Unknown')}")
                print(f"[+] Serial Number: {policy.get('ns0:serial_number', 'Unknown')}")
                print(f"[+] Business UUID: {business.get('ns0:uuid', 'Unknown')}")
            
            # Policy age analysis
            timestamp = policy.get('ns0:updated')
            if timestamp:
                last_update = datetime.datetime.fromtimestamp(int(timestamp) / 1000, tz=datetime.timezone.utc)
                days_old = (datetime.datetime.now(datetime.timezone.utc) - last_update).days
                
                if 'console' in self.formats:
                    print(f"[+] Last Updated: {last_update} ({days_old} days ago)")
                
                if days_old > 365:
                    self.findings.append(self._create_finding(
                        "CRITICAL", "Policy Extremely Outdated",
                        f"Policy not updated for {days_old} days (over 1 year)",
                        "Update policy to current security standards",
                        "Policy Management"
                    ))
                elif days_old > 180:
                    self.findings.append(self._create_finding(
                        "WARNING", "Policy Outdated",
                        f"Policy not updated for {days_old} days",
                        "Review and update policy configuration",
                        "Policy Management"
                    ))
            
            # Policy enabled check
            if header.get('ns0:policy_enabled') == '0':
                self.findings.append(self._create_finding(
                    "CRITICAL", "Policy Disabled",
                    "Main policy enforcement is disabled",
                    "Enable policy enforcement",
                    "Policy Management"
                ))
                
        except Exception as e:
            logger.error(f"Error parsing header: {e}")
    
    def _audit_exclusions_comprehensive(self, exclusions: Dict[str, Any]):
        """Comprehensive exclusions security audit"""
        if not exclusions:
            self.findings.append(self._create_finding(
                "INFO", "No Exclusions Configured",
                "No exclusions are configured in this policy",
                "Consider if any legitimate exclusions are needed",
                "Exclusions"
            ))
            return
            
        if 'console' in self.formats:
            print("\n[+] Comprehensive Exclusion Analysis:")
        
        # File exclusions analysis
        self._audit_file_exclusions(exclusions)
        
        # Certificate exclusions analysis
        self._audit_certificate_exclusions(exclusions)
        
        # Process exclusions analysis
        self._audit_process_exclusions(exclusions)
    
    def _audit_file_exclusions(self, exclusions: Dict[str, Any]):
        """Comprehensive file exclusions audit"""
        items = exclusions.get('ns0:info', {}).get('ns0:item', [])
        if not items:
            return
            
        if 'console' in self.formats:
            print("  File Exclusions Analysis:")
        
        if not isinstance(items, list):
            items = [items]
            
        dangerous_patterns = ['*', '.*', '**', '..']
        broad_exclusions = []
        system_exclusions = []
        temp_exclusions = []
        
        for item in items:
            if isinstance(item, str) and '|' in item:
                parts = item.split('|')
                if len(parts) > 4:
                    path = unquote(parts[4])
                    
                    if 'console' in self.formats:
                        # Check for dangerous patterns
                        for pattern in dangerous_patterns:
                            if pattern in path:
                                self.findings.append(self._create_finding(
                                    "CRITICAL", "Dangerous Wildcard in File Exclusion",
                                    f"Exclusion contains risky pattern: {path}",
                                    "Remove or restrict wildcard usage",
                                    "File Exclusions"
                                ))
                                print(f"    [!] DANGEROUS: {path}")
                                break
                        else:
                            print(f"    - {path}")
                    
                    # Categorize exclusions for analysis
                    path_lower = path.lower()
                    if any(broad in path_lower for broad in ['c:\\', 'd:\\', 'program files']):
                        broad_exclusions.append(path)
                    if any(sys_path in path_lower for sys_path in ['windows\\system32', 'system volume information']):
                        system_exclusions.append(path)
                    if any(temp_path in path_lower for temp_path in ['temp', 'tmp', 'cache']):
                        temp_exclusions.append(path)
        
        # Generate findings based on exclusion analysis
        if broad_exclusions:
            self.findings.append(self._create_finding(
                "WARNING", "Broad File Exclusions",
                f"Found {len(broad_exclusions)} potentially broad exclusions",
                "Review exclusions for necessity and scope",
                "File Exclusions"
            ))
        
        if len(temp_exclusions) > 10:
            self.findings.append(self._create_finding(
                "INFO", "Many Temporary Directory Exclusions",
                f"Found {len(temp_exclusions)} temporary directory exclusions",
                "Review if all temporary exclusions are necessary",
                "File Exclusions"
            ))
    
    def _audit_certificate_exclusions(self, exclusions: Dict[str, Any]):
        """Comprehensive certificate exclusions audit"""
        cert_issuers = exclusions.get('ns0:certissuer', {}).get('ns0:name', [])
        if not cert_issuers:
            return
            
        if 'console' in self.formats:
            print("  Certificate Exclusions Analysis:")
        
        if not isinstance(cert_issuers, list):
            cert_issuers = [cert_issuers]
        
        trusted_issuers = ['Microsoft', 'VeriSign', 'DigiCert', 'Symantec']
        unknown_issuers = []
        
        for issuer in cert_issuers:
            if 'console' in self.formats:
                if '*' in str(issuer):
                    self.findings.append(self._create_finding(
                        "WARNING", "Wildcard in Certificate Exclusion",
                        f"Certificate exclusion uses wildcard: {issuer}",
                        "Use specific certificate issuer names",
                        "Certificate Exclusions"
                    ))
                    print(f"    [!] {issuer}")
                else:
                    print(f"    - {issuer}")
            
            # Check for unknown/untrusted issuers
            if not any(trusted in str(issuer) for trusted in trusted_issuers):
                unknown_issuers.append(str(issuer))
        
        if unknown_issuers:
            self.findings.append(self._create_finding(
                "INFO", "Unknown Certificate Issuers",
                f"Found {len(unknown_issuers)} potentially unknown certificate issuers",
                "Verify the trustworthiness of certificate issuers",
                "Certificate Exclusions"
            ))
    
    def _audit_process_exclusions(self, exclusions: Dict[str, Any]):
        """Comprehensive process exclusions audit"""
        processes = exclusions.get('ns0:process', {}).get('ns0:item', [])
        if not processes:
            return
            
        if 'console' in self.formats:
            print("  Process Exclusions Analysis:")
        
        if not isinstance(processes, list):
            processes = [processes]
        
        system_processes = []
        third_party_processes = []
        wildcard_processes = []
        
        for process in processes:
            process_str = str(process)
            process_decoded = unquote(process_str)
            
            if 'console' in self.formats:
                if '*' in process_str:
                    self.findings.append(self._create_finding(
                        "WARNING", "Wildcard in Process Exclusion",
                        f"Process exclusion uses wildcard: {process_decoded}",
                        "Use specific process paths without wildcards",
                        "Process Exclusions"
                    ))
                    print(f"    [!] {process_decoded}")
                    wildcard_processes.append(process_decoded)
                else:
                    print(f"    - {process_decoded}")
            
            # Categorize processes
            if any(sys_proc in process_decoded.lower() for sys_proc in ['windows\\system32', 'microsoft', 'windows defender']):
                system_processes.append(process_decoded)
            elif any(vendor in process_decoded.lower() for vendor in ['mcafee', 'symantec', 'kaspersky', 'trend micro']):
                third_party_processes.append(process_decoded)
        
        # Generate findings
        if len(wildcard_processes) > 5:
            self.findings.append(self._create_finding(
                "WARNING", "Multiple Wildcard Process Exclusions",
                f"Found {len(wildcard_processes)} process exclusions with wildcards",
                "Minimize wildcard usage in process exclusions",
                "Process Exclusions"
            ))
        
        if len(third_party_processes) > 10:
            self.findings.append(self._create_finding(
                "INFO", "Many Third-Party Process Exclusions",
                f"Found {len(third_party_processes)} third-party security tool exclusions",
                "Regularly review third-party exclusions for necessity",
                "Process Exclusions"
            ))
    
    def _audit_agent_comprehensive(self, agent: Dict[str, Any]):
        """Comprehensive agent security audit"""
        if not agent:
            self.findings.append(self._create_finding(
                "CRITICAL", "No Agent Configuration",
                "No agent security configuration found in policy",
                "Verify policy contains agent configuration",
                "Agent Configuration"
            ))
            return
        
        if 'console' in self.formats:
            print("\n[+] Comprehensive Agent Security Analysis:")
        
        # Platform-specific checks
        if self.policy_type == 'windows':
            self._audit_windows_comprehensive(agent)
        elif self.policy_type in ['mac', 'linux']:
            self._audit_mac_linux_comprehensive(agent)
        elif self.policy_type == 'android':
            self._audit_android_comprehensive(agent)
        
        # Common checks for all platforms
        self._audit_cloud_security_comprehensive(agent.get('ns0:cloud', {}))
        self._audit_scanning_engines_comprehensive(agent.get('ns0:scansettings', {}))
        self._audit_network_monitoring_comprehensive(agent.get('ns0:nfm', {}))
        self._audit_telemetry_comprehensive(agent.get('ns0:telemetry', {}))
        self._audit_command_line_capture(agent.get('ns0:cmdlinecapture', {}))
        self._audit_endpoint_isolation(agent.get('ns0:endpointisolation', {}))
    
    def _audit_windows_comprehensive(self, agent: Dict[str, Any]):
        """Comprehensive Windows-specific security audit"""
        
        # Password protection
        control = agent.get('ns0:control', {})
        if not control.get('ns0:passwordex'):
            self.findings.append(self._create_finding(
                "CRITICAL", "Installation Not Password Protected",
                "AMP installation is not protected by password",
                "Enable password protection in Administrative Features",
                "Windows Security"
            ))
        
        # Service control
        if control.get('ns0:serviceex') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "Service Control Disabled",
                "Enhanced service control is disabled",
                "Enable service control for better protection",
                "Windows Security"
            ))
        
        # Uninstall protection
        if control.get('ns0:uninstallex') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "Uninstall Protection Disabled",
                "Enhanced uninstall protection is disabled",
                "Enable uninstall protection to prevent tampering",
                "Windows Security"
            ))
        
        # Behavioral Protection (APDE)
        self._audit_behavioral_protection(agent.get('ns0:apde', {}))
        
        # Exploit Prevention
        self._audit_exploit_prevention_comprehensive(agent.get('ns0:exprev', {}))
        
        # Script Protection (AMSI)
        self._audit_script_protection_comprehensive(agent.get('ns0:amsi', {}))
        
        # Malicious Activity Protection
        self._audit_malicious_activity_protection(agent.get('ns0:heuristic', {}))
        
        # Windows-specific telemetry
        etw = agent.get('ns0:etw', {})
        if etw.get('ns0:enabled') == '0':
            self.findings.append(self._create_finding(
                "INFO", "Event Tracing Disabled",
                "Event Tracing for Windows (ETW) is disabled",
                "Consider enabling ETW for enhanced visibility",
                "Windows Telemetry"
            ))
        
        # Firewall integration
        firewall = agent.get('ns0:firewall', {})
        if firewall.get('ns0:mode') == 'disabled':
            self.findings.append(self._create_finding(
                "INFO", "Firewall Integration Disabled",
                "Windows firewall integration is disabled",
                "Consider enabling for network protection coordination",
                "Windows Security"
            ))
        
        # Defense mechanisms
        defense = agent.get('ns0:defense', {})
        if defense:
            wfp = defense.get('ns0:wfp', {})
            if wfp.get('ns0:enable') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "Windows Filtering Platform Disabled",
                    "WFP integration is disabled",
                    "Consider enabling WFP for network-level protection",
                    "Windows Security"
                ))
    
    def _audit_behavioral_protection(self, apde: Dict[str, Any]):
        """Audit behavioral protection settings"""
        if apde.get('ns0:enable') == '0':
            self.findings.append(self._create_finding(
                "CRITICAL", "Behavioral Protection Disabled",
                "Advanced behavioral analytics are completely disabled",
                "Enable Behavioral Protection for advanced threat detection",
                "Behavioral Protection"
            ))
        elif apde.get('ns0:mode') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "Behavioral Protection in Audit Mode",
                "Behavioral protection is detecting but not blocking threats",
                "Change to blocking mode for active protection",
                "Behavioral Protection"
            ))
        
        # Check forensic capabilities
        if apde.get('ns0:forensic_snapshot_uri'):
            self.findings.append(self._create_finding(
                "INFO", "Forensic Snapshots Enabled",
                "Forensic snapshot capability is configured",
                "Ensure forensic data handling complies with privacy policies",
                "Behavioral Protection"
            ))
    
    def _audit_exploit_prevention_comprehensive(self, exprev: Dict[str, Any]):
        """Comprehensive exploit prevention audit"""
        if exprev.get('ns0:enable') == '0':
            self.findings.append(self._create_finding(
                "CRITICAL", "Exploit Prevention Disabled",
                "All exploit prevention features are disabled",
                "Enable Exploit Prevention for protection against exploits",
                "Exploit Prevention"
            ))
            return
        
        # Check various exploit prevention versions
        for version in ['v1', 'v3', 'v4', 'v5', 'v8']:
            version_config = exprev.get(f'ns0:{version}')
            if version_config:
                if version == 'v8':
                    self._audit_exprev_v8_features(version_config)
                elif version_config.get('ns0:options'):
                    # Older versions with options field
                    options = version_config.get('ns0:options', '0x0000033B')
                    if options == '0x0000033B':
                        self.findings.append(self._create_finding(
                            "WARNING", f"Exploit Prevention {version.upper()} in Audit Mode",
                            f"Exploit prevention {version} is in audit mode only",
                            f"Configure {version} for blocking mode",
                            "Exploit Prevention"
                        ))
    
    def _audit_exprev_v8_features(self, v8_config: Dict[str, Any]):
        """Audit exploit prevention v8 specific features"""
        features = v8_config.get('ns0:features', {})
        if not features:
            return
        
        feature_list = features.get('ns0:feature', [])
        if not isinstance(feature_list, list):
            feature_list = [feature_list]
        
        feature_states = {}
        for feature in feature_list:
            if isinstance(feature, dict):
                name = feature.get('@name')
                state = feature.get('@state')
                if name:
                    feature_states[name] = state
        
        # Critical v8 features
        critical_features = {
            'EdgeCredentialTheftProtection': 'Edge credential theft protection',
            'ChromeCredentialTheftProtection': 'Chrome credential theft protection',
            'UacRemoteThreadProtection': 'UAC remote thread protection',
            'SmartBlockingProtection': 'Smart blocking protection',
            'MbrOverwriteProtection': 'MBR overwrite protection',
            'OutlookCveProtection': 'Outlook CVE protection',
            'DllMorphingProtection': 'DLL morphing protection',
            'ShellCodeProtection': 'Shell code protection',
            'ScriptControlProtection': 'Script control protection'
        }
        
        for feature_name, description in critical_features.items():
            state = feature_states.get(feature_name, 'unknown')
            if state == 'disabled':
                self.findings.append(self._create_finding(
                    "WARNING", f"{description.title()} Disabled",
                    f"{description} is disabled",
                    f"Enable {description} for enhanced security",
                    "Exploit Prevention v8"
                ))
            elif state == 'audit':
                self.findings.append(self._create_finding(
                    "INFO", f"{description.title()} in Audit Mode",
                    f"{description} is in audit mode only",
                    f"Consider enabling blocking mode for {description}",
                    "Exploit Prevention v8"
                ))
    
    def _audit_script_protection_comprehensive(self, amsi: Dict[str, Any]):
        """Comprehensive script protection audit"""
        if amsi.get('ns0:enable') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "Script Protection Disabled",
                "AMSI (Anti-Malware Scan Interface) is disabled",
                "Enable Script Protection for malicious script detection",
                "Script Protection"
            ))
        elif amsi.get('ns0:mode') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "Script Protection in Audit Mode",
                "AMSI is in audit mode only",
                "Enable blocking mode for script protection",
                "Script Protection"
            ))
        
        # Check Script Control Service
        scs = amsi.get('ns0:scs', {})
        if scs:
            if scs.get('ns0:enable') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "Script Control Service Disabled",
                    "Script Control Service (SCS) is disabled",
                    "Consider enabling SCS for enhanced script analysis",
                    "Script Protection"
                ))
            elif scs.get('ns0:mode') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "Script Control Service in Audit Mode",
                    "SCS is in audit mode only",
                    "Consider enabling blocking mode for SCS",
                    "Script Protection"
                ))
    
    def _audit_malicious_activity_protection(self, heuristic: Dict[str, Any]):
        """Comprehensive malicious activity protection audit"""
        if heuristic.get('ns0:enable') == '0':
            self.findings.append(self._create_finding(
                "CRITICAL", "Malicious Activity Protection Disabled",
                "Heuristic malicious activity detection is disabled",
                "Enable Malicious Activity Protection",
                "Heuristic Protection"
            ))
            return
        
        if heuristic.get('ns0:qaction') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "Malicious Activity Protection in Audit Mode",
                "Heuristic protection is detecting but not blocking",
                "Change to blocking mode for active protection",
                "Heuristic Protection"
            ))
        
        # Ransomware protection analysis
        rw = heuristic.get('ns0:rw', {})
        if rw:
            if rw.get('ns0:enable') == '0':
                self.findings.append(self._create_finding(
                    "CRITICAL", "Ransomware Protection Disabled",
                    "Specific ransomware protection is disabled",
                    "Enable ransomware protection features",
                    "Ransomware Protection"
                ))
            elif rw.get('ns0:mode') == '0':
                self.findings.append(self._create_finding(
                    "WARNING", "Ransomware Protection in Audit Mode",
                    "Ransomware protection is in audit mode only",
                    "Enable blocking mode for ransomware protection",
                    "Ransomware Protection"
                ))
            
            # Analyze ransomware rules
            rules = rw.get('ns0:rule', [])
            if not isinstance(rules, list):
                rules = [rules]
            
            enabled_rules = sum(1 for rule in rules if isinstance(rule, dict) and rule.get('ns0:enable') == '1')
            total_rules = len([rule for rule in rules if isinstance(rule, dict)])
            
            if total_rules > 0:
                if enabled_rules == 0:
                    self.findings.append(self._create_finding(
                        "WARNING", "No Ransomware Rules Enabled",
                        f"All {total_rules} ransomware detection rules are disabled",
                        "Enable appropriate ransomware detection rules",
                        "Ransomware Protection"
                    ))
                elif enabled_rules < total_rules / 2:
                    self.findings.append(self._create_finding(
                        "INFO", "Few Ransomware Rules Enabled",
                        f"Only {enabled_rules} of {total_rules} ransomware rules are enabled",
                        "Review and enable additional ransomware rules as appropriate",
                        "Ransomware Protection"
                    ))
    
    def _audit_mac_linux_comprehensive(self, agent: Dict[str, Any]):
        """Comprehensive Mac/Linux security audit"""
        
        # Driver protection modes
        driver = agent.get('ns0:driver', {})
        protmode = driver.get('ns0:protmode', {})
        
        if protmode.get('ns0:qaction') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "File Blocking in Audit Mode",
                "File blocking is in audit mode only",
                "Enable blocking mode for file protection",
                "File Protection"
            ))
        
        if protmode.get('ns0:process') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "Process Monitoring Disabled",
                "Process execution monitoring is disabled",
                "Enable process monitoring for security visibility",
                "Process Monitoring"
            ))
        
        if protmode.get('ns0:file') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "File Monitoring Disabled",
                "File copy/move monitoring is disabled",
                "Enable file monitoring for comprehensive protection",
                "File Protection"
            ))
        
        if protmode.get('ns0:activeexec') == '0':
            self.findings.append(self._create_finding(
                "INFO", "Active Execution Mode Disabled",
                "On-execute scanning is in passive mode",
                "Consider enabling active execution mode",
                "File Protection"
            ))
        
        # ClamAV engine
        scansettings = agent.get('ns0:scansettings', {})
        clamav = scansettings.get('ns0:clamav', {})
        if clamav.get('ns0:enable') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "ClamAV Engine Disabled",
                "ClamAV signature-based scanning is disabled",
                "Enable ClamAV for signature-based detection",
                "Scanning Engines"
            ))
        
        # Self-protection analysis
        selfprotect = driver.get('ns0:selfprotect', {})
        if selfprotect:
            if selfprotect.get('ns0:spp') == '0':
                self.findings.append(self._create_finding(
                    "WARNING", "System Process Protection Disabled",
                    "System process protection is disabled",
                    "Enable system process protection",
                    "Self Protection"
                ))
            
            if selfprotect.get('ns0:spp_qaction') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "System Process Protection in Audit Mode",
                    "System process protection is in audit mode",
                    "Consider enabling blocking mode",
                    "Self Protection"
                ))
    
    def _audit_android_comprehensive(self, agent: Dict[str, Any]):
        """Comprehensive Android security audit"""
        # Android policies are typically minimal
        cloud = agent.get('ns0:cloud', {})
        if not cloud:
            self.findings.append(self._create_finding(
                "WARNING", "No Cloud Configuration",
                "Cloud lookup is not configured for Android",
                "Configure cloud lookup for threat intelligence",
                "Android Security"
            ))
        
        # Check for basic Android settings
        nfm = agent.get('ns0:nfm', {})
        if not nfm or nfm.get('ns0:enable') == '0':
            self.findings.append(self._create_finding(
                "INFO", "Network Flow Monitoring Disabled",
                "Network monitoring is disabled on Android",
                "Consider enabling NFM if supported",
                "Android Security"
            ))
    
    def _audit_cloud_security_comprehensive(self, cloud: Dict[str, Any]):
        """Comprehensive cloud security audit"""
        if not cloud:
            self.findings.append(self._create_finding(
                "CRITICAL", "No Cloud Configuration",
                "Cloud lookup configuration is missing",
                "Configure cloud lookup for threat intelligence",
                "Cloud Security"
            ))
            return
        
        # TTL analysis
        cache = cloud.get('ns0:cache', {})
        ttls = cache.get('ns0:ttl', {})
        if ttls:
            long_ttl_threshold = 7200  # 2 hours
            very_long_ttl_threshold = 86400  # 24 hours
            
            for ttl_type in ['unknown', 'clean', 'malicious', 'unseen', 'block']:
                ttl_key = f'ns0:{ttl_type}'
                if ttl_key in ttls:
                    ttl_value = int(ttls[ttl_key])
                    if ttl_value > very_long_ttl_threshold:
                        self.findings.append(self._create_finding(
                            "WARNING", f"Very Long TTL for {ttl_type.title()} Lookups",
                            f"TTL for {ttl_type} lookups is {ttl_value} seconds (over 24 hours)",
                            f"Consider reducing TTL for {ttl_type} lookups for timely updates",
                            "Cloud Security"
                        ))
                    elif ttl_value > long_ttl_threshold:
                        self.findings.append(self._create_finding(
                            "INFO", f"Long TTL for {ttl_type.title()} Lookups",
                            f"TTL for {ttl_type} lookups is {ttl_value} seconds",
                            f"Consider reducing TTL for {ttl_type} lookups",
                            "Cloud Security"
                        ))
        
        # Trusted certificates analysis
        trusted_certs = cloud.get('ns0:trustedcerts', {})
        if trusted_certs:
            cert_list = trusted_certs.get('ns0:cert', [])
            if not isinstance(cert_list, list):
                cert_list = [cert_list]
            
            if len(cert_list) == 0:
                self.findings.append(self._create_finding(
                    "WARNING", "No Trusted Certificates",
                    "No trusted certificates configured for cloud communication",
                    "Configure appropriate trusted certificates",
                    "Cloud Security"
                ))
        
        # File extension lookup
        lookup = cloud.get('ns0:lookup', {})
        if lookup:
            fileext = lookup.get('ns0:fileextension', {})
            if fileext.get('ns0:enable') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "File Extension Lookup Disabled",
                    "File extension-based cloud lookup is disabled",
                    "Consider enabling for comprehensive file analysis",
                    "Cloud Security"
                ))
        
        # Job engine settings
        jobengine = cloud.get('ns0:jobengine', {})
        if jobengine:
            max_fs = jobengine.get('ns0:max_fs')
            if max_fs and int(max_fs) > 100 * 1024 * 1024:  # 100MB
                self.findings.append(self._create_finding(
                    "INFO", "Large File Size Limit",
                    f"Maximum file size for analysis is {int(max_fs) // (1024*1024)}MB",
                    "Verify file size limits are appropriate for environment",
                    "Cloud Security"
                ))
    
    def _audit_scanning_engines_comprehensive(self, scansettings: Dict[str, Any]):
        """Comprehensive scanning engines audit"""
        if not scansettings:
            self.findings.append(self._create_finding(
                "WARNING", "No Scan Settings",
                "No scanning engine configuration found",
                "Configure scanning engines appropriately",
                "Scanning Engines"
            ))
            return
        
        # Core engines analysis
        engines = {
            'ethos': ('ETHOS ML engine', 'machine learning'),
            'spero': ('SPERO signature engine', 'signature-based detection'),
            'tetra': ('TETRA emulation engine', 'behavioral emulation')
        }
        
        disabled_engines = []
        
        for engine, (name, description) in engines.items():
            engine_config = scansettings.get(f'ns0:{engine}', {})
            if engine_config.get('ns0:enable') == '0':
                disabled_engines.append(name)
                self.findings.append(self._create_finding(
                    "WARNING", f"{name} Disabled",
                    f"{name} ({description}) is disabled",
                    f"Enable {name} for comprehensive threat detection",
                    "Scanning Engines"
                ))
        
        # TETRA-specific analysis
        tetra = scansettings.get('ns0:tetra', {})
        if tetra.get('ns0:enable') == '1':
            options = tetra.get('ns0:options', {})
            ondemand = options.get('ns0:ondemand', {})
            
            if ondemand.get('ns0:scanarchives') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "TETRA Archive Scanning Disabled",
                    "TETRA engine archive scanning is disabled",
                    "Enable archive scanning for comprehensive coverage",
                    "TETRA Engine"
                ))
            
            if ondemand.get('ns0:scanpacked') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "TETRA Packed File Scanning Disabled",
                    "TETRA engine packed file scanning is disabled",
                    "Enable packed file scanning for thorough analysis",
                    "TETRA Engine"
                ))
            
            if ondemand.get('ns0:deepscan') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "TETRA Deep Scanning Disabled",
                    "TETRA engine deep scanning is disabled",
                    "Enable deep scanning for thorough analysis",
                    "TETRA Engine"
                ))
        
        # Scheduled scanning analysis
        scheduled = scansettings.get('ns0:scheduled', {})
        if scheduled:
            # Handle both single scheduled scan and multiple scheduled scans
            scheduled_list = scheduled if isinstance(scheduled, list) else [scheduled]
            
            for sched_item in scheduled_list:
                if isinstance(sched_item, dict) and sched_item.get('ns0:enable') == '0':
                    self.findings.append(self._create_finding(
                        "INFO", "Scheduled Scans Disabled",
                        "Scheduled scanning is disabled",
                        "Consider enabling scheduled scans for regular system checks",
                        "Scheduled Scanning"
                    ))
                elif isinstance(sched_item, str):
                    # Parse scheduled scan configuration
                    try:
                        parts = sched_item.split('|')
                        if len(parts) >= 3:
                            scan_name = parts[2] if len(parts) > 2 else "Unknown"
                            scan_enabled = parts[1] if len(parts) > 1 else "0"
                            scan_frequency = parts[3] if len(parts) > 3 else "0"
                            
                            if scan_enabled == '0':
                                self.findings.append(self._create_finding(
                                    "INFO", "Scheduled Scan Disabled",
                                    f"Scheduled scan '{scan_name}' is disabled",
                                    "Consider enabling scheduled scans",
                                    "Scheduled Scanning"
                                ))
                            else:
                                # Analyze scan frequency
                                # Frequency codes: 1=daily, 5=weekly, 30=monthly (approximately)
                                try:
                                    freq_value = int(scan_frequency)
                                    if freq_value >= 30:  # Monthly or less frequent
                                        self.findings.append(self._create_finding(
                                            "WARNING", "Infrequent Scheduled Scan",
                                            f"Scheduled scan '{scan_name}' runs monthly or less frequently (frequency: {freq_value})",
                                            "Configure more frequent scans (weekly or daily) for better security coverage",
                                            "Scheduled Scanning"
                                        ))
                                    elif freq_value == 0:
                                        self.findings.append(self._create_finding(
                                            "INFO", "Scheduled Scan Frequency Not Set",
                                            f"Scheduled scan '{scan_name}' has no frequency configured",
                                            "Set appropriate scan frequency for regular security checks",
                                            "Scheduled Scanning"
                                        ))
                                except ValueError:
                                    # Non-numeric frequency, log as info
                                    self.findings.append(self._create_finding(
                                        "INFO", "Custom Scheduled Scan Frequency",
                                        f"Scheduled scan '{scan_name}' uses custom frequency: {scan_frequency}",
                                        "Verify scan frequency meets security requirements",
                                        "Scheduled Scanning"
                                    ))
                    except Exception:
                        self.findings.append(self._create_finding(
                            "WARNING", "Invalid Scheduled Scan Configuration",
                            "Scheduled scan configuration format is invalid",
                            "Review and correct scheduled scan configuration",
                            "Scheduled Scanning"
                        ))
        else:
            # No scheduled scans configured
            self.findings.append(self._create_finding(
                "WARNING", "No Scheduled Scans Configured",
                "No scheduled scans are configured in this policy",
                "Configure regular scheduled scans for proactive threat detection",
                "Scheduled Scanning"
            ))
        
        # Engine performance analysis
        if len(disabled_engines) >= 2:
            self.findings.append(self._create_finding(
                "WARNING", "Multiple Scanning Engines Disabled",
                f"{len(disabled_engines)} scanning engines are disabled",
                "Enable multiple engines for layered protection",
                "Scanning Engines"
            ))
    
    def _audit_network_monitoring_comprehensive(self, nfm: Dict[str, Any]):
        """Comprehensive network monitoring audit"""
        if nfm.get('ns0:enable') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "Network Flow Monitoring Disabled",
                "Network traffic monitoring is completely disabled",
                "Enable NFM for network threat detection",
                "Network Monitoring"
            ))
            return
        
        settings = nfm.get('ns0:settings', {})
        if settings:
            if settings.get('ns0:qaction') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "Network Flow Monitoring in Audit Mode",
                    "NFM is in audit mode only",
                    "Consider enabling blocking mode for active protection",
                    "Network Monitoring"
                ))
            
            # Check for device monitoring
            if settings.get('ns0:monitor_device') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "Device Monitoring Disabled",
                    "Device-level network monitoring is disabled",
                    "Consider enabling device monitoring",
                    "Network Monitoring"
                ))
    
    def _audit_telemetry_comprehensive(self, telemetry: Dict[str, Any]):
        """Comprehensive telemetry audit"""
        if not telemetry:
            self.findings.append(self._create_finding(
                "INFO", "No Telemetry Configuration",
                "Telemetry collection is not configured",
                "Consider enabling telemetry for enhanced threat intelligence",
                "Telemetry"
            ))
            return
        
        # APDE telemetry
        apde_telemetry = telemetry.get('ns0:apde', {})
        if apde_telemetry:
            if apde_telemetry.get('ns0:enable') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "APDE Telemetry Disabled",
                    "Behavioral analytics telemetry is disabled",
                    "Consider enabling for improved threat detection",
                    "Telemetry"
                ))
    
    def _audit_command_line_capture(self, cmdline: Dict[str, Any]):
        """Audit command line capture settings"""
        if cmdline.get('ns0:enable') == '0':
            self.findings.append(self._create_finding(
                "INFO", "Command Line Capture Disabled",
                "Command line logging is disabled",
                "Enable for forensic and investigation capabilities",
                "Command Line Capture"
            ))
            return
        
        # Environment variable filtering
        envflt = cmdline.get('ns0:envflt', {})
        if envflt:
            patterns = envflt.get('ns0:pattern', [])
            if not isinstance(patterns, list):
                patterns = [patterns]
            
            # Check for common sensitive environment variables
            sensitive_vars = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL']
            filtered_sensitive = [p for p in patterns if any(var in str(p).upper() for var in sensitive_vars)]
            
            if len(patterns) == 0:
                self.findings.append(self._create_finding(
                    "INFO", "No Environment Variable Filtering",
                    "No environment variable filtering configured",
                    "Consider filtering sensitive environment variables",
                    "Privacy Protection"
                ))
            elif len(filtered_sensitive) == 0:
                self.findings.append(self._create_finding(
                    "WARNING", "No Sensitive Variable Filtering",
                    "No filtering for sensitive environment variables detected",
                    "Add filters for PASSWORD, SECRET, KEY, TOKEN variables",
                    "Privacy Protection"
                ))
    
    def _audit_endpoint_isolation(self, isolation: Dict[str, Any]):
        """Audit endpoint isolation capabilities"""
        if isolation.get('ns0:enable') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "Endpoint Isolation Disabled",
                "Endpoint isolation capability is disabled",
                "Enable for incident response capabilities",
                "Incident Response"
            ))
            return
        
        # Proxy access during isolation
        if isolation.get('ns0:allowproxy') == '1':
            self.findings.append(self._create_finding(
                "INFO", "Proxy Access Allowed During Isolation",
                "Proxy access is allowed when endpoint is isolated",
                "Review if proxy access should be blocked during isolation",
                "Incident Response"
            ))
    
    def _audit_connection_security(self, config: Dict[str, Any]):
        """Audit connection security settings"""
        conn = config.get('ns0:conn', {})
        if not conn:
            return
        
        ssl = conn.get('ns0:ssl', {})
        if ssl:
            if ssl.get('ns0:verifyhost') == '0':
                self.findings.append(self._create_finding(
                    "WARNING", "SSL Host Verification Disabled",
                    "SSL hostname verification is disabled",
                    "Enable SSL host verification for secure connections",
                    "Connection Security"
                ))
            
            if ssl.get('ns0:verifypeer') == '0':
                self.findings.append(self._create_finding(
                    "WARNING", "SSL Peer Verification Disabled",
                    "SSL peer certificate verification is disabled",
                    "Enable SSL peer verification for secure connections",
                    "Connection Security"
                ))
            
            if ssl.get('ns0:crlc') == '0':
                self.findings.append(self._create_finding(
                    "INFO", "Certificate Revocation Checking Disabled",
                    "Certificate revocation list checking is disabled",
                    "Consider enabling CRL checking for enhanced security",
                    "Connection Security"
                ))
    
    def _audit_update_security(self, config: Dict[str, Any]):
        """Audit update mechanism security"""
        updater = config.get('ns0:updater', {})
        if not updater:
            return
        
        # Update window analysis
        window_start = updater.get('ns0:window_start')
        window_end = updater.get('ns0:window_end')
        
        if window_start and window_end:
            self.findings.append(self._create_finding(
                "INFO", "Update Window Configured",
                f"Updates restricted to window: {window_start} - {window_end}",
                "Ensure update window allows timely security updates",
                "Update Management"
            ))
        
        # Reboot policy
        if updater.get('ns0:block_reboot') == '1':
            self.findings.append(self._create_finding(
                "WARNING", "Reboot Blocked for Updates",
                "System reboots are blocked for updates",
                "Allow reboots for critical security updates",
                "Update Management"
            ))
        
        # Update interval
        interval = updater.get('ns0:interval')
        if interval and int(interval) > 86400:  # 24 hours
            self.findings.append(self._create_finding(
                "INFO", "Long Update Interval",
                f"Update check interval is {int(interval) // 3600} hours",
                "Consider more frequent update checks for timely protection",
                "Update Management"
            ))
    
    def _audit_ui_security(self, config: Dict[str, Any]):
        """Audit user interface security settings"""
        ui = config.get('ns0:ui', {})
        if not ui:
            return
        
        # Exclusions visibility
        exclusions = ui.get('ns0:exclusions', {})
        if exclusions.get('ns0:display') == '1':
            self.findings.append(self._create_finding(
                "WARNING", "Exclusions Visible to Users",
                "Exclusion lists are visible in the user interface",
                "Hide exclusions from end users to prevent circumvention",
                "User Interface Security"
            ))
        
        # Notification settings
        notifications = ui.get('ns0:notification', {})
        if notifications:
            # Check various notification types
            notification_types = {
                'ns0:cloud': 'Cloud notifications',
                'ns0:hide_file_toast': 'File notifications',
                'ns0:hide_nfm_toast': 'Network flow notifications',
                'ns0:hide_detection_toast': 'Detection notifications',
                'ns0:hide_heuristic_toast': 'Heuristic notifications',
                'ns0:hide_exprev_toast': 'Exploit prevention notifications'
            }
            
            visible_notifications = []
            for key, description in notification_types.items():
                if key in notifications:
                    if (key == 'ns0:cloud' and notifications[key] == '1') or \
                       (key.startswith('ns0:hide_') and notifications[key] == '0'):
                        visible_notifications.append(description)
            
            if len(visible_notifications) > 3:
                self.findings.append(self._create_finding(
                    "INFO", "Many User Notifications Enabled",
                    f"{len(visible_notifications)} notification types are visible to users",
                    "Consider reducing notification verbosity for end users",
                    "User Interface Security"
                ))
            
            if notifications.get('ns0:verbose') == '1':
                self.findings.append(self._create_finding(
                    "INFO", "Verbose Notifications Enabled",
                    "Verbose logging notifications are shown to users",
                    "Consider disabling verbose notifications for end users",
                    "User Interface Security"
                ))
    
    def _audit_orbital_security(self, orbital: Dict[str, Any]):
        """Audit Orbital threat hunting platform settings"""
        if not orbital:
            self.findings.append(self._create_finding(
                "INFO", "Orbital Not Configured",
                "Orbital threat hunting platform is not configured",
                "Consider enabling Orbital for advanced threat hunting",
                "Threat Hunting"
            ))
            return
        
        # Check if Orbital is enabled
        if orbital.get('ns0:enablemsi') == '0' or orbital.get('ns0:enable') == '0':
            self.findings.append(self._create_finding(
                "WARNING", "Orbital Disabled",
                "Orbital threat hunting platform is disabled",
                "Enable Orbital for advanced threat hunting capabilities",
                "Threat Hunting"
            ))
        
        # Check update configuration
        updater = orbital.get('ns0:updater', {})
        if updater:
            interval = updater.get('ns0:interval')
            if interval and int(interval) > 86400:  # 24 hours
                self.findings.append(self._create_finding(
                    "INFO", "Long Orbital Update Interval",
                    f"Orbital update interval is {int(interval) // 3600} hours",
                    "Consider more frequent updates for current threat intelligence",
                    "Threat Hunting"
                ))
    
    def _get_nested_value(self, keys: List[str]) -> Optional[Dict[str, Any]]:
        """Safely get nested dictionary values"""
        current = self.policy_data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current
    
    def _print_summary(self):
        """Print audit summary to console"""
        print("\n" + "="*80)
        print("COMPREHENSIVE AUDIT SUMMARY")
        print("="*80)
        
        if not self.findings:
            print("[+] No security issues found!")
        else:
            # Group findings by severity and category
            severity_counts = {'CRITICAL': 0, 'WARNING': 0, 'INFO': 0}
            category_counts = {}
            
            for finding in self.findings:
                severity = finding.get('severity', 'INFO')
                category = finding.get('category', 'General')
                
                severity_counts[severity] += 1
                category_counts[category] = category_counts.get(category, 0) + 1
            
            # Print severity summary
            if severity_counts['CRITICAL'] > 0:
                print(f"\n[!] CRITICAL ISSUES ({severity_counts['CRITICAL']}):")
                for finding in self.findings:
                    if finding.get('severity') == 'CRITICAL':
                        print(f"  - {finding['title']}: {finding['description']}")
            
            if severity_counts['WARNING'] > 0:
                print(f"\n[*] WARNINGS ({severity_counts['WARNING']}):")
                for finding in self.findings:
                    if finding.get('severity') == 'WARNING':
                        print(f"  - {finding['title']}: {finding['description']}")
            
            if severity_counts['INFO'] > 0:
                print(f"\n[i] INFORMATIONAL ({severity_counts['INFO']}):")
                for finding in self.findings:
                    if finding.get('severity') == 'INFO':
                        print(f"  - {finding['title']}: {finding['description']}")
            
            # Print category summary
            print("\n" + "-"*80)
            print("FINDINGS BY CATEGORY:")
            for category, count in sorted(category_counts.items()):
                print(f"  {category}: {count} finding(s)")
        
        print("\n" + "="*80)
    
    def _generate_reports(self):
        """Generate reports in requested formats"""
        if 'json' in self.formats:
            self._generate_json_report()
        
        if 'html' in self.formats:
            self._generate_html_report()
        
        if 'csv' in self.formats:
            self._generate_csv_report()
    
    def _generate_json_report(self):
        """Generate JSON report"""
        policy_name = self.policy_path.stem
        json_file = self.output_dir / f"{policy_name}_audit.json"
        
        report_data = {
            'policy_info': {
                'file_path': str(self.policy_path),
                'policy_type': self.policy_type,
                'audit_timestamp': datetime.datetime.now().isoformat()
            },
            'findings': self.findings,
            'summary': self._generate_findings_summary()
        }
        
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"[+] JSON report saved to: {json_file}")
    
    def _generate_html_report(self):
        """Generate HTML report"""
        policy_name = self.policy_path.stem
        html_file = self.output_dir / f"{policy_name}_audit.html"
        
        summary = self._generate_findings_summary()
        
        # Group findings by category
        categorized = {}
        for finding in self.findings:
            category = finding.get('category', 'General')
            if category not in categorized:
                categorized[category] = {'CRITICAL': [], 'WARNING': [], 'INFO': []}
            
            severity = finding.get('severity', 'INFO')
            categorized[category][severity].append(finding)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprehensive Policy Audit - {policy_name}</title>
    <style>
        body {{ margin: 0; padding: 20px; background-color: #f5f7fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 4px solid #0066cc; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #0066cc; margin: 0 0 10px 0; font-size: 2.5em; }}
        .header h2 {{ color: #555; margin: 0; font-weight: 300; }}
        .metadata {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .metadata strong {{ color: #e8f4f8; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .summary-card {{ padding: 25px; border-radius: 10px; text-align: center; color: white; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }}
        .critical {{ background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); }}
        .warning {{ background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%); color: #2d3436; }}
        .info {{ background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%); }}
        .summary-card h3 {{ margin: 0 0 15px 0; font-size: 1.2em; }}
        .summary-card .count {{ font-size: 3em; font-weight: bold; margin-bottom: 10px; }}
        .category {{ margin-bottom: 40px; }}
        .category h2 {{ color: #2d3436; border-bottom: 3px solid #74b9ff; padding-bottom: 10px; font-size: 1.8em; }}
        .finding {{ margin-bottom: 20px; padding: 20px; border-radius: 8px; border-left: 5px solid; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .finding.critical {{ background: linear-gradient(135deg, #ffe8e8 0%, #ffcccb 100%); border-color: #ff6b6b; }}
        .finding.warning {{ background: linear-gradient(135deg, #fff8e1 0%, #ffe0b2 100%); border-color: #feca57; }}
        .finding.info {{ background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%); border-color: #74b9ff; }}
        .finding-title {{ font-weight: bold; margin-bottom: 10px; font-size: 1.1em; }}
        .finding-severity {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: bold; color: white; margin-right: 10px; }}
        .finding-severity.critical {{ background: #ff6b6b; }}
        .finding-severity.warning {{ background: #feca57; color: #2d3436; }}
        .finding-severity.info {{ background: #74b9ff; }}
        .finding-description {{ margin-bottom: 15px; color: #555; line-height: 1.6; }}
        .recommendation {{ padding: 15px; background: rgba(0,0,0,0.05); border-radius: 5px; border-left: 3px solid #00b894; }}
        .recommendation::before {{ content: "💡 Recommendation: "; font-weight: bold; color: #00b894; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 2px solid #ddd; text-align: center; color: #74818e; }}
        .footer a {{ color: #0066cc; text-decoration: none; }}
        .footer a:hover {{ text-decoration: underline; }}
        .no-findings {{ text-align: center; padding: 60px; color: #00b894; }}
        .no-findings h3 {{ font-size: 2em; margin-bottom: 15px; }}
        .github-link {{ background: #24292e; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none; }}
        .github-link:hover {{ background: #444d56; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Comprehensive Security Audit</h1>
            <h2>{policy_name}</h2>
        </div>
        
        <div class="metadata">
            <strong>Policy File:</strong> {self.policy_path.name}<br>
            <strong>Policy Type:</strong> {self.policy_type.upper()}<br>
            <strong>Audit Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
            <strong>Total Findings:</strong> {len(self.findings)}
        </div>
        
        <div class="summary">
            <div class="summary-card critical">
                <h3>Critical Issues</h3>
                <div class="count">{summary['critical']}</div>
                <p>Immediate attention required</p>
            </div>
            <div class="summary-card warning">
                <h3>Warnings</h3>
                <div class="count">{summary['warning']}</div>
                <p>Should be addressed</p>
            </div>
            <div class="summary-card info">
                <h3>Informational</h3>
                <div class="count">{summary['info']}</div>
                <p>For consideration</p>
            </div>
        </div>
"""

        if summary['total'] == 0:
            html_content += """
        <div class="no-findings">
            <h3>✅ Excellent Security Posture!</h3>
            <p>This policy configuration appears to be well-secured with no significant issues found.</p>
        </div>
"""
        else:
            for category, severity_groups in categorized.items():
                if any(severity_groups.values()):
                    html_content += f"""
        <div class="category">
            <h2>🛡️ {category}</h2>
"""
                    
                    for severity in ['CRITICAL', 'WARNING', 'INFO']:
                        for finding in severity_groups[severity]:
                            html_content += f"""
            <div class="finding {severity.lower()}">
                <div class="finding-title">
                    <span class="finding-severity {severity.lower()}">{severity}</span>
                    {finding['title']}
                </div>
                <div class="finding-description">{finding['description']}</div>
                {f'<div class="recommendation">{finding["recommendation"]}</div>' if finding.get('recommendation') else ''}
            </div>
"""
                    
                    html_content += """
        </div>
"""

        html_content += f"""
        <div class="footer">
            <p><strong>Generated by Cisco Secure Endpoint Policy Auditor (Comprehensive Mode)</strong></p>
            <p>Author: <strong>Jerzy 'Yuri' Kramarz (op7ic)</strong> | 
            <a href="https://github.com/op7ic/amp-policy-kit" target="_blank" class="github-link">📚 GitHub Repository</a></p>
            <p>Report generated on {datetime.datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}</p>
            <p><em>This tool helps ensure your Cisco Secure Endpoint policies maintain strong security posture</em></p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report saved to: {html_file}")
    
    def _generate_csv_report(self):
        """Generate CSV report"""
        policy_name = self.policy_path.stem
        csv_file = self.output_dir / f"{policy_name}_audit.csv"
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Policy File', 'Policy Type', 'Severity', 'Category',
                'Title', 'Description', 'Recommendation', 'Timestamp'
            ])
            
            for finding in self.findings:
                writer.writerow([
                    self.policy_path.name,
                    self.policy_type,
                    finding.get('severity', ''),
                    finding.get('category', ''),
                    finding.get('title', ''),
                    finding.get('description', ''),
                    finding.get('recommendation', ''),
                    finding.get('timestamp', '')
                ])
        
        print(f"[+] CSV report saved to: {csv_file}")
    
    def _generate_findings_summary(self) -> Dict[str, int]:
        """Generate summary statistics"""
        summary = {'critical': 0, 'warning': 0, 'info': 0, 'total': len(self.findings)}
        
        for finding in self.findings:
            severity = finding.get('severity', 'INFO').lower()
            if severity == 'critical':
                summary['critical'] += 1
            elif severity == 'warning':
                summary['warning'] += 1
            else:
                summary['info'] += 1
        
        return summary


def validate_file(filepath: str) -> str:
    """Validate that the file exists and is readable"""
    path = Path(filepath)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"File not found: {filepath}")
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"Not a file: {filepath}")
    return str(path)


def validate_directory(dirpath: str) -> str:
    """Validate or create directory"""
    path = Path(dirpath)
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Cisco Secure Endpoint Comprehensive Policy Auditor - Offline Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Console output only
  %(prog)s -i policy.xml
  
  # Generate reports in multiple formats
  %(prog)s -i policy.xml -o reports/ --formats html json csv
  
  # Just HTML report
  %(prog)s -i policy.xml -o reports/ --formats html
  
  # Verbose console output with JSON report
  %(prog)s -i policy.xml -o reports/ --formats console json -v
        """
    )
    
    parser.add_argument(
        "-i", "--input",
        dest="policy_path",
        required=True,
        help="Path to AMP/Secure Endpoint XML or plist policy file",
        type=validate_file,
        metavar="FILE"
    )
    
    parser.add_argument(
        "-o", "--output",
        dest="output_dir",
        help="Output directory for reports (optional)",
        type=validate_directory,
        metavar="DIR"
    )
    
    parser.add_argument(
        "--formats",
        nargs='+',
        choices=['console', 'json', 'html', 'csv'],
        default=['console'],
        help="Output formats (default: console)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create auditor and run audit
    auditor = ComprehensivePolicyAuditor(args.policy_path, args.output_dir, args.formats)
    
    if not auditor.load_policy():
        logger.error("Failed to load policy file")
        sys.exit(1)
        
    auditor.audit()


if __name__ == "__main__":
    main()