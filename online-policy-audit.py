#!/usr/bin/env python3
"""
Cisco Secure Endpoint Policy Auditor - Comprehensive Online Mode
Connects to Cisco Secure Endpoint API to audit all policies with detailed per-policy reports

Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file in this repository
GitHub: https://github.com/op7ic/amp-policy-kit
"""

import sys
import requests
import configparser
import datetime
import json
import argparse
import logging
import csv
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from urllib.parse import unquote
from xml.etree.ElementTree import fromstring, ElementTree, tostring
import concurrent.futures
import re

try:
    import xmltodict
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing required dependencies")
    print("[!] Please install: pip3 install xmltodict beautifulsoup4")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class ComprehensivePolicyAuditor:
    """Comprehensive auditor for Cisco Secure Endpoint policies"""
    
    def __init__(self, config_path: str, output_dir: str, formats: List[str] = None):
        self.config = self._load_config(config_path)
        self.output_dir = Path(output_dir)
        self.session = self._create_session()
        self.policies = []
        self.audit_results = {}
        self.formats = formats or ['json', 'html']
        
        # Create output directory structure
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'policies').mkdir(exist_ok=True)
        (self.output_dir / 'invalid_policies').mkdir(exist_ok=True)
        
    def _load_config(self, config_path: str) -> configparser.ConfigParser:
        """Load configuration from file"""
        config = configparser.ConfigParser()
        if not config.read(config_path):
            raise ValueError(f"Failed to read config file: {config_path}")
            
        required = [('api', 'client_id'), ('api', 'api_key'), ('api', 'domainIP')]
        for section, key in required:
            if not config.has_option(section, key):
                raise ValueError(f"Missing required config: [{section}] {key}")
                
        return config
    
    def _create_session(self) -> requests.Session:
        """Create authenticated session"""
        session = requests.Session()
        session.auth = (
            self.config.get('api', 'client_id'),
            self.config.get('api', 'api_key')
        )
        session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': 'AMP-Policy-Auditor-Comprehensive/2.0'
        })
        return session
    
    def fetch_policies(self) -> bool:
        """Fetch all policies from the API"""
        try:
            base_url = f"https://{self.config.get('api', 'domainIP')}/v1/policies"
            
            logger.info("Fetching policies from API...")
            
            all_policies = []
            offset = 0
            limit = 500
            
            while True:
                params = {'offset': offset, 'limit': limit}
                response = self.session.get(base_url, params=params)
                response.raise_for_status()
                
                data = response.json()
                policies = data.get('data', [])
                all_policies.extend(policies)
                
                metadata = data.get('metadata', {})
                total = metadata.get('results', {}).get('total', 0)
                
                if offset + limit >= total:
                    break
                    
                offset += limit
            
            self.policies = all_policies
            logger.info(f"Found {len(self.policies)} policies")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch policies: {e}")
            return False
    
    def audit_all_policies(self):
        """Audit all policies and generate comprehensive reports"""
        if not self.policies:
            logger.warning("No policies to audit")
            return
            
        print("\n" + "="*80)
        print("CISCO SECURE ENDPOINT COMPREHENSIVE POLICY AUDIT")
        print("="*80)
        print(f"\nAuditing {len(self.policies)} policies...\n")
        
        # Process policies in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_policy = {
                executor.submit(self._audit_single_policy, policy): policy 
                for policy in self.policies
            }
            
            for future in concurrent.futures.as_completed(future_to_policy):
                policy = future_to_policy[future]
                try:
                    result = future.result()
                    if result:
                        self.audit_results[policy['guid']] = result
                        self._generate_per_policy_reports(result)
                except Exception as e:
                    logger.error(f"Error auditing policy {policy.get('name', 'Unknown')}: {e}")
        
        # Generate summary reports
        self._generate_summary_reports()
    
    def _audit_single_policy(self, policy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Perform comprehensive audit of a single policy"""
        try:
            # Fetch XML
            policy_xml_url = f"https://{self.config.get('api', 'domainIP')}/v1/policies/{policy['guid']}.xml"
            response = self.session.get(policy_xml_url)
            response.raise_for_status()
            
            # Parse XML
            policy_data = self._parse_policy_xml(response.text)
            if not policy_data:
                self._save_invalid_policy(policy, response.text, "Failed to parse XML")
                return None
            
            # Extract policy metadata from XML (more reliable than API metadata)
            xml_metadata = self._extract_xml_metadata(policy_data)
            
            # Comprehensive audit
            findings = self._comprehensive_policy_audit(policy, policy_data)
            
            return {
                'name': xml_metadata.get('name', policy['name']),
                'guid': policy['guid'],
                'product': policy.get('product', 'Unknown'),
                'findings': findings,
                'policy_data': policy_data,
                'raw_xml': response.text,
                'metadata': {
                    'xml_name': xml_metadata.get('name'),
                    'xml_last_modified': xml_metadata.get('last_modified'),
                    'xml_serial_number': xml_metadata.get('serial_number'),
                    'xml_business_uuid': xml_metadata.get('business_uuid'),
                    'api_last_modified': policy.get('modified_at'),
                    'api_serial_number': policy.get('serial_number'),
                    'description': policy.get('description', ''),
                    'audit_timestamp': datetime.datetime.now().isoformat(),
                    'policy_age_days': xml_metadata.get('age_days', 0)
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to audit policy {policy['name']}: {e}")
            try:
                # Try to save invalid policy if we have XML content
                if 'response' in locals():
                    self._save_invalid_policy(policy, response.text, str(e))
            except:
                pass
            return None
    
    def _parse_policy_xml(self, xml_content: str) -> Optional[Dict[str, Any]]:
        """Parse policy XML content (handles both standard XML and iOS plist)"""
        try:
            # Check if this is an iOS plist format
            if '<!DOCTYPE plist' in xml_content or '<plist' in xml_content:
                return self._parse_ios_plist(xml_content)
            else:
                # Standard XML parsing
                tree = ElementTree(fromstring(xml_content))
                root = tree.getroot()
                
                soup = BeautifulSoup(tostring(root), "xml")
                policy_dict = xmltodict.parse(soup.prettify(), dict_constructor=dict)
                
                return policy_dict
                
        except Exception as e:
            logger.error(f"Failed to parse policy XML: {e}")
            return None
    
    def _parse_ios_plist(self, xml_content: str) -> Optional[Dict[str, Any]]:
        """Parse iOS plist XML content using plistlib"""
        try:
            import plistlib
            
            # Parse using plistlib for proper plist handling
            plist_data = plistlib.loads(xml_content.encode('utf-8'))
            
            # Convert to a structure that mimics xmltodict for consistency
            return {'plist': plist_data}
            
        except Exception as e:
            logger.debug(f"Failed to parse as plist, falling back to XML: {e}")
            try:
                # Fallback to XML parsing
                tree = ElementTree(fromstring(xml_content))
                root = tree.getroot()
                
                soup = BeautifulSoup(tostring(root), "xml")
                policy_dict = xmltodict.parse(soup.prettify(), dict_constructor=dict)
                
                return policy_dict
            except Exception as e2:
                logger.error(f"Failed to parse iOS policy: {e2}")
                return None
    
    def _extract_xml_metadata(self, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata from XML policy data (handles standard XML and iOS plist formats)"""
        metadata = {
            'name': 'Unknown',
            'serial_number': 'Unknown',
            'business_uuid': 'Unknown', 
            'last_modified': None,
            'age_days': 0
        }
        
        try:
            # Check if this is an iOS plist format
            if 'plist' in policy_data:
                # iOS plist format - already parsed by plistlib
                plist_data = policy_data['plist']
                
                # Extract basic plist metadata
                if 'PayloadDisplayName' in plist_data:
                    metadata['name'] = plist_data['PayloadDisplayName']
                
                if 'PayloadOrganization' in plist_data:
                    metadata['business_uuid'] = plist_data['PayloadOrganization']
                
                # Look for VendorConfig in PayloadContent
                payload_content = plist_data.get('PayloadContent', [])
                if isinstance(payload_content, list):
                    for payload in payload_content:
                        if isinstance(payload, dict) and 'VendorConfig' in payload:
                            vendor_config = payload['VendorConfig']
                            
                            if 'business_guid' in vendor_config:
                                metadata['business_uuid'] = vendor_config['business_guid']
                            
                            # Look for any policy identification info
                            if 'policy_name' in vendor_config:
                                metadata['name'] = vendor_config['policy_name']
                            
                            break
                
                # Extract creation date if available
                if 'PayloadCreationDate' in plist_data:
                    try:
                        creation_date = plist_data['PayloadCreationDate']
                        if hasattr(creation_date, 'isoformat'):
                            # It's a datetime object from plistlib
                            if creation_date.tzinfo is None:
                                creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)
                            metadata['last_modified'] = creation_date.isoformat()
                            age_days = (datetime.datetime.now(datetime.timezone.utc) - creation_date).days
                            metadata['age_days'] = age_days
                    except Exception as e:
                        logger.debug(f"Failed to parse iOS creation date: {e}")
                
                # If we still don't have a good name, try PayloadContent items
                if metadata['name'] == 'Unknown' and isinstance(payload_content, list):
                    for payload in payload_content:
                        if isinstance(payload, dict) and 'PayloadDisplayName' in payload:
                            display_name = payload['PayloadDisplayName']
                            if 'Cisco' in display_name or 'AMP' in display_name:
                                metadata['name'] = display_name
                                break
                            
            else:
                # Standard XML format
                header = self._get_nested_value(policy_data, ['ns0:Signature', 'ns0:Object', 'ns0:config', 'ns0:janus'])
                if header:
                    policy_info = header.get('ns0:policy', {})
                    business_info = header.get('ns0:business', {})
                    
                    metadata['name'] = policy_info.get('ns0:name', 'Unknown')
                    metadata['serial_number'] = policy_info.get('ns0:serial_number', 'Unknown')
                    metadata['business_uuid'] = business_info.get('ns0:uuid', 'Unknown')
                    
                    # Parse timestamp and calculate age
                    timestamp = policy_info.get('ns0:updated')
                    if timestamp:
                        try:
                            last_update = datetime.datetime.fromtimestamp(int(timestamp) / 1000, tz=datetime.timezone.utc)
                            metadata['last_modified'] = last_update.isoformat()
                            
                            # Calculate age in days
                            age_days = (datetime.datetime.now(datetime.timezone.utc) - last_update).days
                            metadata['age_days'] = age_days
                            
                        except (ValueError, TypeError) as e:
                            logger.warning(f"Failed to parse timestamp {timestamp}: {e}")
                            metadata['last_modified'] = None
                            metadata['age_days'] = 0
                    else:
                        metadata['last_modified'] = None
                        metadata['age_days'] = 0
                    
        except Exception as e:
            logger.warning(f"Failed to extract XML metadata: {e}")
            
        return metadata
    
    
    def _save_invalid_policy(self, policy: Dict[str, Any], xml_content: str, error_msg: str):
        """Save invalid policy XML to separate folder"""
        try:
            invalid_dir = self.output_dir / 'invalid_policies'
            policy_name = policy.get('name', 'Unknown').replace(' ', '_').replace('/', '_')
            filename = f"{policy_name}_{policy['guid'][:8]}.xml"
            
            invalid_file = invalid_dir / filename
            with open(invalid_file, 'w', encoding='utf-8') as f:
                f.write(f"<!-- ERROR: {error_msg} -->\n")
                f.write(f"<!-- Policy Name: {policy.get('name', 'Unknown')} -->\n")
                f.write(f"<!-- Policy GUID: {policy['guid']} -->\n")
                f.write(f"<!-- Product: {policy.get('product', 'Unknown')} -->\n")
                f.write(f"<!-- Timestamp: {datetime.datetime.now().isoformat()} -->\n")
                f.write(xml_content)
            
            logger.warning(f"Saved invalid policy XML to: {invalid_file}")
            
        except Exception as e:
            logger.error(f"Failed to save invalid policy: {e}")
    
    def _format_timestamp(self, timestamp: str) -> str:
        """Convert Unix timestamp to readable ISO format"""
        try:
            if timestamp and timestamp.isdigit():
                dt = datetime.datetime.fromtimestamp(int(timestamp), tz=datetime.timezone.utc)
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            return timestamp
        except (ValueError, TypeError):
            return timestamp
    
    def _comprehensive_policy_audit(self, policy_meta: Dict[str, Any], policy_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform comprehensive audit of policy data"""
        findings = []
        
        # Get config root
        config = self._get_nested_value(policy_data, ['ns0:Signature', 'ns0:Object', 'ns0:config'])
        if not config:
            findings.append(self._create_finding("CRITICAL", "Invalid policy structure", "Policy XML structure is invalid"))
            return findings
        
        # 1. Policy Age and Update Analysis
        findings.extend(self._audit_policy_age(policy_meta))
        
        # 2. Exclusions Analysis
        findings.extend(self._audit_exclusions_comprehensive(config.get('ns0:exclusions', {})))
        
        # 3. Agent Security Settings
        agent = config.get('ns0:agent', {})
        if agent:
            findings.extend(self._audit_agent_comprehensive(agent, policy_meta.get('product', '').lower()))
        
        # 4. Connection Security
        findings.extend(self._audit_connection_security(config))
        
        # 5. Update Security
        findings.extend(self._audit_update_security(config))
        
        # 6. UI Security
        findings.extend(self._audit_ui_security(config))
        
        # 7. Orbital Security
        findings.extend(self._audit_orbital_security(config.get('ns0:orbital', {})))
        
        # 8. Scheduled Scans
        findings.extend(self._audit_scheduled_scans(agent.get('ns0:scansettings', {})))
        
        return findings
    
    def _create_finding(self, severity: str, title: str, description: str, 
                       recommendation: str = "", category: str = "General") -> Dict[str, Any]:
        """Create a standardized finding dictionary"""
        return {
            'severity': severity,
            'title': title,
            'description': description,
            'recommendation': recommendation,
            'category': category,
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    def _audit_policy_age(self, policy_meta: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit policy age and update frequency using XML metadata"""
        findings = []
        
        # Use XML metadata for more accurate age calculation
        xml_last_modified = policy_meta.get('xml_last_modified')
        age_days = policy_meta.get('policy_age_days', 0)
        
        if xml_last_modified and age_days > 0:
            # Use original logic: 12 months = 365 days threshold
            if age_days > 365:
                findings.append(self._create_finding(
                    "CRITICAL", "Policy Extremely Outdated", 
                    f"Policy not updated for {age_days} days (over 12 months). Last updated: {xml_last_modified}",
                    "Immediately update policy to current security standards and threat landscape",
                    "Policy Management"
                ))
            elif age_days > 180:
                findings.append(self._create_finding(
                    "WARNING", "Policy Outdated",
                    f"Policy not updated for {age_days} days (over 6 months). Last updated: {xml_last_modified}",
                    "Review and update policy configuration to ensure current protections",
                    "Policy Management"
                ))
            elif age_days > 90:
                findings.append(self._create_finding(
                    "INFO", "Policy Should Be Reviewed",
                    f"Policy not updated for {age_days} days. Last updated: {xml_last_modified}",
                    "Consider reviewing policy for updates and improvements",
                    "Policy Management"
                ))
        else:
            # Fallback to API metadata if XML parsing failed
            api_modified = policy_meta.get('api_last_modified')
            if api_modified:
                try:
                    modified = datetime.datetime.fromisoformat(api_modified.replace('Z', '+00:00'))
                    age_days = (datetime.datetime.now(datetime.timezone.utc) - modified).days
                    
                    if age_days > 365:
                        findings.append(self._create_finding(
                            "CRITICAL", "Policy Extremely Outdated",
                            f"Policy not updated for {age_days} days (over 12 months, from API)",
                            "Update policy to current security standards",
                            "Policy Management"
                        ))
                except Exception:
                    findings.append(self._create_finding(
                        "INFO", "Unable to Determine Policy Age",
                        "Policy modification timestamp could not be parsed from XML or API",
                        "Verify policy metadata and update timestamp",
                        "Policy Management"
                    ))
        
        return findings
    
    def _audit_exclusions_comprehensive(self, exclusions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Comprehensive exclusions audit"""
        findings = []
        
        # File exclusions
        items = exclusions.get('ns0:info', {}).get('ns0:item', [])
        if items:
            if not isinstance(items, list):
                items = [items]
            
            dangerous_patterns = ['*', '.*', '**', '..']
            broad_exclusions = []
            
            for item in items:
                if isinstance(item, str) and '|' in item:
                    parts = item.split('|')
                    if len(parts) > 4:
                        path = unquote(parts[4])
                        
                        # Check for dangerous wildcards
                        for pattern in dangerous_patterns:
                            if pattern in path:
                                findings.append(self._create_finding(
                                    "CRITICAL", "Dangerous Wildcard in File Exclusion",
                                    f"Exclusion contains risky pattern: {path}",
                                    "Remove or restrict wildcard usage in exclusions",
                                    "Exclusions"
                                ))
                                break
                        
                        # Check for overly broad exclusions
                        if any(broad in path.lower() for broad in ['c:\\', 'd:\\', 'temp', 'users']):
                            broad_exclusions.append(path)
            
            if broad_exclusions:
                findings.append(self._create_finding(
                    "WARNING", "Broad File Exclusions Detected",
                    f"Found {len(broad_exclusions)} potentially broad exclusions",
                    "Review exclusions for necessity and scope",
                    "Exclusions"
                ))
        
        # Certificate exclusions
        cert_issuers = exclusions.get('ns0:certissuer', {}).get('ns0:name', [])
        if cert_issuers:
            if not isinstance(cert_issuers, list):
                cert_issuers = [cert_issuers]
            
            for issuer in cert_issuers:
                if '*' in str(issuer):
                    findings.append(self._create_finding(
                        "WARNING", "Wildcard in Certificate Exclusion",
                        f"Certificate exclusion uses wildcard: {issuer}",
                        "Specify exact certificate issuer names",
                        "Exclusions"
                    ))
        
        # Process exclusions
        processes = exclusions.get('ns0:process', {}).get('ns0:item', [])
        if processes:
            if not isinstance(processes, list):
                processes = [processes]
            
            for process in processes:
                if '*' in str(process):
                    findings.append(self._create_finding(
                        "WARNING", "Wildcard in Process Exclusion",
                        f"Process exclusion uses wildcard: {unquote(str(process))}",
                        "Use specific process paths without wildcards",
                        "Exclusions"
                    ))
        
        return findings
    
    def _audit_agent_comprehensive(self, agent: Dict[str, Any], product: str) -> List[Dict[str, Any]]:
        """Comprehensive agent security audit"""
        findings = []
        
        if 'windows' in product:
            findings.extend(self._audit_windows_specific(agent))
        elif 'mac' in product or 'linux' in product:
            findings.extend(self._audit_mac_linux_specific(agent))
        
        # Common checks
        findings.extend(self._audit_common_agent_settings(agent))
        findings.extend(self._audit_cloud_security(agent.get('ns0:cloud', {})))
        findings.extend(self._audit_scanning_engines(agent.get('ns0:scansettings', {})))
        findings.extend(self._audit_telemetry_security(agent.get('ns0:telemetry', {})))
        
        return findings
    
    def _audit_windows_specific(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Windows-specific security checks"""
        findings = []
        
        # Password protection
        control = agent.get('ns0:control', {})
        if not control.get('ns0:passwordex'):
            findings.append(self._create_finding(
                "CRITICAL", "Installation Not Password Protected",
                "AMP installation is not protected by password",
                "Enable password protection in Administrative Features",
                "Windows Security"
            ))
        
        # Behavioral Protection (APDE)
        apde = agent.get('ns0:apde', {})
        if apde.get('ns0:enable') == '0':
            findings.append(self._create_finding(
                "CRITICAL", "Behavioral Protection Disabled",
                "Advanced behavioral analytics are disabled",
                "Enable Behavioral Protection in Modes and Engines",
                "Windows Security"
            ))
        elif apde.get('ns0:mode') == '0':
            findings.append(self._create_finding(
                "WARNING", "Behavioral Protection in Audit Mode",
                "Behavioral protection is detecting but not blocking",
                "Change to blocking mode for active protection",
                "Windows Security"
            ))
        
        # Exploit Prevention
        findings.extend(self._audit_exploit_prevention(agent.get('ns0:exprev', {})))
        
        # AMSI Script Protection
        amsi = agent.get('ns0:amsi', {})
        if amsi.get('ns0:enable') == '0':
            findings.append(self._create_finding(
                "WARNING", "Script Protection Disabled",
                "Anti-Malware Scan Interface (AMSI) is disabled",
                "Enable Script Protection for malicious script detection",
                "Windows Security"
            ))
        elif amsi.get('ns0:mode') == '0':
            findings.append(self._create_finding(
                "WARNING", "Script Protection in Audit Mode",
                "AMSI is in audit mode only",
                "Enable blocking mode for script protection",
                "Windows Security"
            ))
        
        # Malicious Activity Protection
        findings.extend(self._audit_heuristic_protection(agent.get('ns0:heuristic', {})))
        
        # Windows-specific telemetry
        etw = agent.get('ns0:etw', {})
        if etw.get('ns0:enabled') == '0':
            findings.append(self._create_finding(
                "INFO", "Event Tracing for Windows Disabled",
                "ETW collection is disabled",
                "Consider enabling for enhanced visibility",
                "Windows Security"
            ))
        
        # Firewall integration
        firewall = agent.get('ns0:firewall', {})
        if firewall.get('ns0:mode') == 'disabled':
            findings.append(self._create_finding(
                "INFO", "Firewall Integration Disabled",
                "Windows firewall integration is disabled",
                "Consider enabling for network protection",
                "Windows Security"
            ))
        
        return findings
    
    def _audit_exploit_prevention(self, exprev: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Comprehensive exploit prevention audit"""
        findings = []
        
        if exprev.get('ns0:enable') == '0':
            findings.append(self._create_finding(
                "CRITICAL", "Exploit Prevention Disabled",
                "All exploit prevention features are disabled",
                "Enable Exploit Prevention in Modes and Engines",
                "Exploit Prevention"
            ))
            return findings
        
        # Check v8 features if available
        v8 = exprev.get('ns0:v8', {})
        if v8:
            features = v8.get('ns0:features', {})
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
            
            # Critical features check
            critical_features = {
                'EdgeCredentialTheftProtection': 'Edge credential theft protection',
                'ChromeCredentialTheftProtection': 'Chrome credential theft protection',
                'UacRemoteThreadProtection': 'UAC remote thread protection',
                'SmartBlockingProtection': 'Smart blocking protection',
                'MbrOverwriteProtection': 'MBR overwrite protection',
                'OutlookCveProtection': 'Outlook CVE protection'
            }
            
            for feature_name, description in critical_features.items():
                state = feature_states.get(feature_name, 'unknown')
                if state == 'disabled':
                    findings.append(self._create_finding(
                        "WARNING", f"{description.title()} Disabled",
                        f"{description} is disabled",
                        f"Enable {description} for enhanced security",
                        "Exploit Prevention"
                    ))
                elif state == 'audit':
                    findings.append(self._create_finding(
                        "INFO", f"{description.title()} in Audit Mode",
                        f"{description} is in audit mode only",
                        f"Consider enabling blocking mode for {description}",
                        "Exploit Prevention"
                    ))
        
        return findings
    
    def _audit_heuristic_protection(self, heuristic: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit malicious activity protection"""
        findings = []
        
        if heuristic.get('ns0:enable') == '0':
            findings.append(self._create_finding(
                "CRITICAL", "Malicious Activity Protection Disabled",
                "Heuristic malicious activity detection is disabled",
                "Enable Malicious Activity Protection",
                "Behavioral Analysis"
            ))
            return findings
        
        if heuristic.get('ns0:qaction') == '0':
            findings.append(self._create_finding(
                "WARNING", "Malicious Activity Protection in Audit Mode",
                "Heuristic protection is detecting but not blocking",
                "Change to blocking mode for active protection",
                "Behavioral Analysis"
            ))
        
        # Ransomware protection
        rw = heuristic.get('ns0:rw', {})
        if rw:
            if rw.get('ns0:enable') == '0':
                findings.append(self._create_finding(
                    "CRITICAL", "Ransomware Protection Disabled",
                    "Specific ransomware protection is disabled",
                    "Enable ransomware protection features",
                    "Ransomware Protection"
                ))
            elif rw.get('ns0:mode') == '0':
                findings.append(self._create_finding(
                    "WARNING", "Ransomware Protection in Audit Mode",
                    "Ransomware protection is in audit mode only",
                    "Enable blocking mode for ransomware protection",
                    "Ransomware Protection"
                ))
            
            # Check ransomware rules
            rules = rw.get('ns0:rule', [])
            if not isinstance(rules, list):
                rules = [rules]
            
            enabled_rules = sum(1 for rule in rules if isinstance(rule, dict) and rule.get('ns0:enable') == '1')
            if len(rules) > 0 and enabled_rules == 0:
                findings.append(self._create_finding(
                    "WARNING", "No Ransomware Rules Enabled",
                    "Ransomware detection rules are disabled",
                    "Enable appropriate ransomware detection rules",
                    "Ransomware Protection"
                ))
        
        return findings
    
    def _audit_mac_linux_specific(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Mac/Linux specific security checks"""
        findings = []
        
        # Driver settings
        driver = agent.get('ns0:driver', {})
        protmode = driver.get('ns0:protmode', {})
        
        if protmode.get('ns0:qaction') == '0':
            findings.append(self._create_finding(
                "WARNING", "File Blocking in Audit Mode",
                "File blocking is in audit mode only",
                "Enable blocking mode for file protection",
                "File Protection"
            ))
        
        if protmode.get('ns0:process') == '0':
            findings.append(self._create_finding(
                "WARNING", "Process Monitoring Disabled",
                "Process execution monitoring is disabled",
                "Enable process monitoring for better visibility",
                "Process Monitoring"
            ))
        
        if protmode.get('ns0:file') == '0':
            findings.append(self._create_finding(
                "WARNING", "File Monitoring Disabled",
                "File copy/move monitoring is disabled",
                "Enable file monitoring for comprehensive protection",
                "File Protection"
            ))
        
        # ClamAV engine
        clamav = agent.get('ns0:scansettings', {}).get('ns0:clamav', {})
        if clamav.get('ns0:enable') == '0':
            findings.append(self._create_finding(
                "WARNING", "ClamAV Engine Disabled",
                "ClamAV signature-based scanning is disabled",
                "Enable ClamAV for signature-based detection",
                "Scanning Engines"
            ))
        
        return findings
    
    def _audit_common_agent_settings(self, agent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Common agent settings audit"""
        findings = []
        
        # Network Flow Monitoring
        nfm = agent.get('ns0:nfm', {})
        if nfm.get('ns0:enable') == '0':
            findings.append(self._create_finding(
                "WARNING", "Network Flow Monitoring Disabled",
                "Network traffic monitoring is disabled",
                "Enable NFM for network threat detection",
                "Network Monitoring"
            ))
        elif nfm.get('ns0:settings', {}).get('ns0:qaction') == '0':
            findings.append(self._create_finding(
                "INFO", "Network Flow Monitoring in Audit Mode",
                "NFM is in audit mode only",
                "Consider enabling blocking mode",
                "Network Monitoring"
            ))
        
        # Command Line Capture
        cmdline = agent.get('ns0:cmdlinecapture', {})
        if cmdline.get('ns0:enable') == '0':
            findings.append(self._create_finding(
                "INFO", "Command Line Capture Disabled",
                "Command line logging is disabled",
                "Enable for forensic capabilities",
                "Logging"
            ))
        
        # Environment filtering
        envflt = cmdline.get('ns0:envflt', {})
        if envflt:
            patterns = envflt.get('ns0:pattern', [])
            if not isinstance(patterns, list):
                patterns = [patterns]
            
            if len(patterns) == 0:
                findings.append(self._create_finding(
                    "INFO", "No Environment Variable Filtering",
                    "No environment variable filtering configured",
                    "Consider filtering sensitive environment variables",
                    "Privacy"
                ))
        
        # Endpoint Isolation
        isolation = agent.get('ns0:endpointisolation', {})
        if isolation.get('ns0:enable') == '0':
            findings.append(self._create_finding(
                "WARNING", "Endpoint Isolation Disabled",
                "Endpoint isolation capability is disabled",
                "Enable for incident response capabilities",
                "Incident Response"
            ))
        
        return findings
    
    def _audit_cloud_security(self, cloud: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit cloud lookup security settings"""
        findings = []
        
        if not cloud:
            findings.append(self._create_finding(
                "CRITICAL", "No Cloud Configuration",
                "Cloud lookup is not configured",
                "Configure cloud lookup for threat intelligence",
                "Cloud Security"
            ))
            return findings
        
        # TTL analysis
        ttls = cloud.get('ns0:cache', {}).get('ns0:ttl', {})
        if ttls:
            long_ttl_threshold = 7200  # 2 hours
            
            for ttl_type in ['unknown', 'clean', 'malicious', 'unseen', 'block']:
                ttl_key = f'ns0:{ttl_type}'
                if ttl_key in ttls:
                    ttl_value = int(ttls[ttl_key])
                    if ttl_value > long_ttl_threshold:
                        findings.append(self._create_finding(
                            "INFO", f"Long TTL for {ttl_type.title()} Lookups",
                            f"TTL for {ttl_type} hash lookups is {ttl_value} seconds",
                            f"Consider reducing TTL for {ttl_type} lookups",
                            "Cloud Security"
                        ))
        
        # File extension checking
        fileext = cloud.get('ns0:lookup', {}).get('ns0:fileextension', {})
        if fileext and fileext.get('ns0:enable') == '0':
            findings.append(self._create_finding(
                "INFO", "File Extension Lookup Disabled",
                "File extension-based cloud lookup is disabled",
                "Consider enabling for comprehensive file analysis",
                "Cloud Security"
            ))
        
        return findings
    
    def _audit_scanning_engines(self, scansettings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit scanning engine configurations"""
        findings = []
        
        engines = {
            'ethos': 'ETHOS ML engine',
            'spero': 'SPERO signature engine',
            'tetra': 'TETRA emulation engine'
        }
        
        for engine, name in engines.items():
            engine_config = scansettings.get(f'ns0:{engine}', {})
            if engine_config.get('ns0:enable') == '0':
                findings.append(self._create_finding(
                    "WARNING", f"{name.title()} Disabled",
                    f"{name} is disabled",
                    f"Enable {name} for comprehensive threat detection",
                    "Scanning Engines"
                ))
            elif engine == 'tetra' and engine_config.get('ns0:enable') == '1':
                # TETRA-specific checks
                options = engine_config.get('ns0:options', {}).get('ns0:ondemand', {})
                if options.get('ns0:scanarchives') == '0':
                    findings.append(self._create_finding(
                        "INFO", "TETRA Archive Scanning Disabled",
                        "TETRA engine archive scanning is disabled",
                        "Enable archive scanning for comprehensive coverage",
                        "Scanning Engines"
                    ))
                if options.get('ns0:deepscan') == '0':
                    findings.append(self._create_finding(
                        "INFO", "TETRA Deep Scanning Disabled",
                        "TETRA engine deep scanning is disabled",
                        "Enable deep scanning for thorough analysis",
                        "Scanning Engines"
                    ))
        
        return findings
    
    def _audit_telemetry_security(self, telemetry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit telemetry and data collection settings"""
        findings = []
        
        if not telemetry:
            findings.append(self._create_finding(
                "INFO", "No Telemetry Configuration",
                "Telemetry collection is not configured",
                "Consider enabling for enhanced threat intelligence",
                "Telemetry"
            ))
            return findings
        
        apde_telemetry = telemetry.get('ns0:apde', {})
        if apde_telemetry and apde_telemetry.get('ns0:enable') == '0':
            findings.append(self._create_finding(
                "INFO", "APDE Telemetry Disabled",
                "Behavioral analytics telemetry is disabled",
                "Consider enabling for improved threat detection",
                "Telemetry"
            ))
        
        return findings
    
    def _audit_connection_security(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit connection security settings"""
        findings = []
        
        conn = config.get('ns0:conn', {})
        if conn:
            ssl = conn.get('ns0:ssl', {})
            if ssl:
                if ssl.get('ns0:verifyhost') == '0':
                    findings.append(self._create_finding(
                        "WARNING", "SSL Host Verification Disabled",
                        "SSL hostname verification is disabled",
                        "Enable SSL host verification for secure connections",
                        "Connection Security"
                    ))
                
                if ssl.get('ns0:verifypeer') == '0':
                    findings.append(self._create_finding(
                        "WARNING", "SSL Peer Verification Disabled",
                        "SSL peer verification is disabled",
                        "Enable SSL peer verification for secure connections",
                        "Connection Security"
                    ))
        
        return findings
    
    def _audit_update_security(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit update mechanism security"""
        findings = []
        
        updater = config.get('ns0:updater', {})
        if updater:
            # Check update window
            window_start = updater.get('ns0:window_start')
            window_end = updater.get('ns0:window_end')
            
            if window_start and window_end:
                # Format timestamps for display
                start_formatted = self._format_timestamp(window_start)
                end_formatted = self._format_timestamp(window_end)
                findings.append(self._create_finding(
                    "INFO", "Update Window Configured",
                    f"Updates restricted to window: {start_formatted} - {end_formatted}",
                    "Ensure update window allows timely security updates",
                    "Update Management"
                ))
            
            # Check reboot policy
            if updater.get('ns0:block_reboot') == '1':
                findings.append(self._create_finding(
                    "WARNING", "Reboot Blocked for Updates",
                    "System reboots are blocked for updates",
                    "Allow reboots for security updates when necessary",
                    "Update Management"
                ))
        
        return findings
    
    def _audit_ui_security(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit UI security settings"""
        findings = []
        
        ui = config.get('ns0:ui', {})
        if ui:
            # Check if exclusions are visible to users
            exclusions = ui.get('ns0:exclusions', {})
            if exclusions.get('ns0:display') == '1':
                findings.append(self._create_finding(
                    "WARNING", "Exclusions Visible to Users",
                    "Exclusion lists are visible in the user interface",
                    "Hide exclusions from end users",
                    "User Interface"
                ))
            
            # Check notification settings
            notifications = ui.get('ns0:notification', {})
            if notifications:
                verbose = notifications.get('ns0:verbose')
                if verbose == '1':
                    findings.append(self._create_finding(
                        "INFO", "Verbose Notifications Enabled",
                        "Verbose logging notifications are shown to users",
                        "Consider reducing notification verbosity",
                        "User Interface"
                    ))
        
        return findings
    
    def _audit_orbital_security(self, orbital: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit Orbital security settings"""
        findings = []
        
        if not orbital:
            findings.append(self._create_finding(
                "INFO", "Orbital Not Configured",
                "Orbital threat hunting platform is not configured",
                "Consider enabling Orbital for advanced threat hunting",
                "Threat Hunting"
            ))
            return findings
        
        if orbital.get('ns0:enablemsi') == '0' or orbital.get('ns0:enable') == '0':
            findings.append(self._create_finding(
                "WARNING", "Orbital Disabled",
                "Orbital threat hunting platform is disabled",
                "Enable Orbital for advanced threat hunting capabilities",
                "Threat Hunting"
            ))
        
        return findings
    
    def _audit_scheduled_scans(self, scansettings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit scheduled scan configurations"""
        findings = []
        
        scheduled = scansettings.get('ns0:scheduled', {})
        if scheduled:
            if isinstance(scheduled, dict) and scheduled.get('ns0:enable') == '0':
                findings.append(self._create_finding(
                    "INFO", "Scheduled Scans Disabled",
                    "Scheduled scanning is disabled",
                    "Consider enabling scheduled scans for regular system checks",
                    "Scheduled Scanning"
                ))
            elif isinstance(scheduled, str):
                # Parse scheduled scan string format
                try:
                    parts = scheduled.split('|')
                    if len(parts) >= 4:
                        scan_name = parts[2] if len(parts) > 2 else "Unknown"
                        findings.append(self._create_finding(
                            "INFO", "Scheduled Scan Configured",
                            f"Scheduled scan configured: {scan_name}",
                            "Verify scheduled scan configuration is appropriate",
                            "Scheduled Scanning"
                        ))
                except Exception:
                    findings.append(self._create_finding(
                        "WARNING", "Invalid Scheduled Scan Configuration",
                        "Scheduled scan configuration format is invalid",
                        "Review and correct scheduled scan configuration",
                        "Scheduled Scanning"
                    ))
        
        return findings
    
    def _get_nested_value(self, data: Dict[str, Any], keys: List[str]) -> Optional[Dict[str, Any]]:
        """Safely get nested dictionary values"""
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current
    
    def _generate_per_policy_reports(self, result: Dict[str, Any]):
        """Generate individual policy reports in multiple formats"""
        policy_name = result['name'].replace(' ', '_').replace('/', '_')
        policy_dir = self.output_dir / 'policies' / f"{policy_name}_{result['guid'][:8]}"
        policy_dir.mkdir(exist_ok=True)
        
        # Generate reports in requested formats
        if 'json' in self.formats:
            self._generate_json_report(result, policy_dir)
        
        if 'html' in self.formats:
            self._generate_html_report(result, policy_dir)
        
        if 'csv' in self.formats:
            self._generate_csv_report(result, policy_dir)
    
    def _generate_json_report(self, result: Dict[str, Any], output_dir: Path):
        """Generate JSON report for a policy"""
        json_file = output_dir / 'audit_report.json'
        
        # Remove policy_data to reduce file size (keep findings)
        report_data = {
            'policy_info': {
                'name': result['name'],
                'guid': result['guid'],
                'product': result['product'],
                'metadata': result['metadata']
            },
            'findings': result['findings'],
            'summary': self._generate_findings_summary(result['findings'])
        }
        
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
    
    def _generate_html_report(self, result: Dict[str, Any], output_dir: Path):
        """Generate HTML report for a policy"""
        html_file = output_dir / 'audit_report.html'
        
        findings = result['findings']
        summary = self._generate_findings_summary(findings)
        
        # Group findings by category and severity
        categorized = {}
        for finding in findings:
            category = finding.get('category', 'General')
            if category not in categorized:
                categorized[category] = {'CRITICAL': [], 'WARNING': [], 'INFO': []}
            
            severity = finding.get('severity', 'INFO')
            categorized[category][severity].append(finding)
        
        # Get XML metadata for display
        xml_name = result['metadata'].get('name', result['name']) 
        xml_last_modified = result['metadata'].get('last_modified', 'Unknown')
        xml_serial = result['metadata'].get('serial_number', 'Unknown')
        xml_business = result['metadata'].get('business_uuid', 'Unknown')
        policy_age_days = result['metadata'].get('age_days', 0)
        
        # Determine age status
        age_status = "recent"
        age_color = "#28a745"  # green
        if policy_age_days > 365:
            age_status = "critical"
            age_color = "#dc3545"  # red
        elif policy_age_days > 180:
            age_status = "warning" 
            age_color = "#ffc107"  # yellow
        elif policy_age_days > 90:
            age_status = "caution"
            age_color = "#fd7e14"  # orange

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Policy Audit Report - {xml_name}</title>
    <style>
        body {{ margin: 0; padding: 20px; background-color: #f5f7fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 4px solid #0066cc; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #0066cc; margin: 0 0 10px 0; font-size: 2.5em; }}
        .header h2 {{ color: #555; margin: 0; font-weight: 300; }}
        .metadata {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .metadata strong {{ color: #e8f4f8; }}
        .metadata-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 15px; }}
        .metadata-item {{ background: rgba(255,255,255,0.1); padding: 10px; border-radius: 5px; word-wrap: break-word; overflow-wrap: break-word; }}
        .age-indicator {{ display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; color: white; margin-left: 10px; }}
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
        .appendix {{ margin-top: 50px; }}
        .appendix h2 {{ color: #495057; border-top: 2px solid #dee2e6; padding-top: 20px; }}
        .xml-dump {{ background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px; padding: 20px; font-family: 'Courier New', monospace; font-size: 0.9em; max-height: 500px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word; overflow-wrap: break-word; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 2px solid #ddd; text-align: center; color: #74818e; }}
        .footer a {{ color: #0066cc; text-decoration: none; }}
        .footer a:hover {{ text-decoration: underline; }}
        .no-findings {{ text-align: center; padding: 60px; color: #00b894; }}
        .no-findings h3 {{ font-size: 2em; margin-bottom: 15px; }}
        .github-link {{ background: #24292e; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none; }}
        .github-link:hover {{ background: #444d56; color: white; }}
        .toc {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .toc h3 {{ margin-top: 0; color: #495057; }}
        .toc ul {{ list-style: none; padding-left: 0; }}
        .toc li {{ margin-bottom: 5px; }}
        .toc a {{ color: #0066cc; text-decoration: none; }}
        .toc a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Security Audit Report</h1>
            <h2>{xml_name}</h2>
        </div>
        
        <div class="metadata">
            <strong>📋 Policy Information</strong>
            <div class="metadata-grid">
                <div class="metadata-item">
                    <strong>Name:</strong> {xml_name}
                </div>
                <div class="metadata-item">
                    <strong>GUID:</strong> {result['guid']}
                </div>
                <div class="metadata-item">
                    <strong>Product:</strong> {result['product'].upper()}
                </div>
                <div class="metadata-item">
                    <strong>Serial Number:</strong> {xml_serial}
                </div>
                <div class="metadata-item">
                    <strong>Business UUID:</strong> {xml_business}
                </div>
                <div class="metadata-item">
                    <strong>Last Modified:</strong> {xml_last_modified}
                    <span class="age-indicator" style="background-color: {age_color};">
                        {policy_age_days} days ago
                    </span>
                </div>
                <div class="metadata-item">
                    <strong>Audit Date:</strong> {result['metadata']['audit_timestamp'].replace('T', ' ').replace('Z', ' UTC')}
                </div>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card critical">
                <h3>Critical Issues</h3>
                <div class="count">{summary['critical']}</div>
            </div>
            <div class="summary-card warning">
                <h3>Warnings</h3>
                <div class="count">{summary['warning']}</div>
            </div>
            <div class="summary-card info">
                <h3>Informational</h3>
                <div class="count">{summary['info']}</div>
            </div>
        </div>
"""

        if summary['total'] == 0:
            html_content += """
        <div class="no-findings">
            <h3>✓ No Security Issues Found</h3>
            <p>This policy configuration appears to be secure.</p>
        </div>
"""
        else:
            for category, severity_groups in categorized.items():
                if any(severity_groups.values()):
                    html_content += f"""
        <div class="category">
            <h2 id="{category.lower().replace(' ', '-')}">{category}</h2>
"""
                    
                    for severity in ['CRITICAL', 'WARNING', 'INFO']:
                        for finding in severity_groups[severity]:
                            html_content += f"""
            <div class="finding {severity.lower()}">
                <div class="finding-title">
                    <span class="finding-severity {severity.lower()}">{severity}</span>
                    {finding['title']}
                </div>
                <div>{finding['description']}</div>
                {f'<div class="recommendation"><strong>Recommendation:</strong> {finding["recommendation"]}</div>' if finding.get('recommendation') else ''}
            </div>
"""
                    
                    html_content += """
        </div>
"""

        # Add table of contents if there are findings
        if summary['total'] > 0:
            toc_html = f'''        <div class="toc">
            <h3>📑 Table of Contents</h3>
            <ul>
{self._generate_toc_items(categorized)}
            </ul>
        </div>
        '''
            # Insert TOC before summary
            html_content = html_content.replace('<div class="summary">', toc_html + '<div class="summary">')
        
        # Generate verbose audit output
        verbose_audit = self._generate_verbose_audit_output(result)
        
        # Add XML dump appendix
        xml_dump = self._format_xml_for_display(result.get('raw_xml', 'XML data not available'))
        
        html_content += f"""
        <div class="appendix">
            <h2 id="verbose-audit">🔍 Verbose Policy Audit</h2>
            <p>Detailed policy analysis similar to offline audit --verbose mode:</p>
            <div class="xml-dump">{verbose_audit}</div>
            
            <h2 id="xml-appendix">📄 Policy XML Dump</h2>
            <p>Complete XML policy configuration for technical reference:</p>
            <div class="xml-dump">{xml_dump}</div>
        </div>
        
        <div class="footer">
            <p>Generated by <strong>Cisco Secure Endpoint Policy Auditor</strong></p>
            <p>Author: Jerzy 'Yuri' Kramarz (op7ic) | 
            <a href="https://github.com/op7ic/amp-policy-kit" target="_blank">GitHub Repository</a></p>
            <p>Report generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_toc_items(self, categorized: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> str:
        """Generate table of contents items for findings"""
        toc_items = []
        for category, severity_groups in categorized.items():
            if any(severity_groups.values()):
                total_in_category = sum(len(findings) for findings in severity_groups.values())
                toc_items.append(
                    f'                <li><a href="#{category.lower().replace(" ", "-")}">{category} ({total_in_category} finding{"s" if total_in_category != 1 else ""})</a></li>'
                )
        toc_items.append('                <li><a href="#verbose-audit">Verbose Policy Audit</a></li>')
        toc_items.append('                <li><a href="#xml-appendix">Policy XML Dump</a></li>')
        return '\n'.join(toc_items)
    
    def _generate_verbose_audit_output(self, result: Dict[str, Any]) -> str:
        """Generate verbose audit output exactly like offline comprehensive auditor"""
        import html
        from urllib.parse import unquote
        
        # Get policy data and run the exact same analysis as offline auditor
        policy_data = result.get('policy_data', {})
        metadata = result.get('metadata', {})
        
        # Create an offline-style auditor to generate the exact same output
        verbose_lines = []
        
        # Header
        verbose_lines.append("=" * 80)
        verbose_lines.append("CISCO SECURE ENDPOINT COMPREHENSIVE POLICY AUDIT")
        verbose_lines.append("=" * 80)
        verbose_lines.append("")
        
        # Policy information
        verbose_lines.append(f"[+] Policy Name: {metadata.get('name', result.get('name', 'Unknown'))}")
        verbose_lines.append(f"[+] Policy Type: {result.get('product', 'Unknown').upper()}")
        verbose_lines.append(f"[+] Policy UUID: {result.get('guid', 'Unknown')}")
        verbose_lines.append(f"[+] Serial Number: {metadata.get('serial_number', 'Unknown')}")
        verbose_lines.append(f"[+] Business UUID: {metadata.get('business_uuid', 'Unknown')}")
        verbose_lines.append(f"[+] Last Updated: {metadata.get('last_modified', 'Unknown')} ({metadata.get('age_days', 0)} days ago)")
        verbose_lines.append("")
        
        # Comprehensive Exclusion Analysis - exactly like offline
        if policy_data:
            config = self._get_nested_value(policy_data, ['ns0:Signature', 'ns0:Object', 'ns0:config'])
            exclusions = config.get('ns0:exclusions') if config else None
            
            if exclusions:
                verbose_lines.append("[+] Comprehensive Exclusion Analysis:")
                
                # File Exclusions Analysis
                file_exclusions = self._get_nested_value(exclusions, ['ns0:info', 'ns0:item'])
                if file_exclusions:
                    verbose_lines.append("  File Exclusions Analysis:")
                    
                    # Convert to list if single item
                    if not isinstance(file_exclusions, list):
                        file_exclusions = [file_exclusions]
                    
                    dangerous_patterns = []
                    regular_exclusions = []
                    
                    for exclusion in file_exclusions:
                        if isinstance(exclusion, str) and '|' in exclusion:
                            parts = exclusion.split('|')
                            if len(parts) > 4:
                                path = unquote(parts[4])
                            else:
                                path = unquote(exclusion)
                        else:
                            path = unquote(str(exclusion))
                        
                        # Check for dangerous patterns
                        if any(pattern in path for pattern in ['*', '.*', '**']):
                            dangerous_patterns.append(path)
                        else:
                            regular_exclusions.append(path)
                    
                    # Show all regular exclusions (no truncation)
                    for exclusion in regular_exclusions:
                        verbose_lines.append(f"    - {exclusion}")
                    
                    # Show dangerous patterns
                    for dangerous in dangerous_patterns:
                        verbose_lines.append(f"    [!] DANGEROUS: {dangerous}")
                
                # Certificate Exclusions Analysis
                cert_exclusions = self._get_nested_value(exclusions, ['ns0:certissuer', 'ns0:name'])
                if cert_exclusions:
                    verbose_lines.append("  Certificate Exclusions Analysis:")
                    
                    if not isinstance(cert_exclusions, list):
                        cert_exclusions = [cert_exclusions]
                    
                    for cert in cert_exclusions:
                        cert_name = unquote(str(cert))
                        if '*' in cert_name:
                            verbose_lines.append(f"    [!] {cert_name}")
                        else:
                            verbose_lines.append(f"    - {cert_name}")
                
                # Process Exclusions Analysis
                process_exclusions = self._get_nested_value(exclusions, ['ns0:process', 'ns0:item'])
                if process_exclusions:
                    verbose_lines.append("  Process Exclusions Analysis:")
                    
                    if not isinstance(process_exclusions, list):
                        process_exclusions = [process_exclusions]
                    
                    for process in process_exclusions:
                        process_str = unquote(str(process))
                        if '*' in process_str:
                            verbose_lines.append(f"    [!] {process_str}")
                        else:
                            verbose_lines.append(f"    - {process_str}")
                
                verbose_lines.append("")
            
            # Agent Security Analysis
            agent = config.get('ns0:agent') if config else None
            if agent:
                verbose_lines.append("[+] Comprehensive Agent Security Analysis:")
                verbose_lines.append("")
        
        # Comprehensive Audit Summary - exactly like offline
        if result.get('findings'):
            verbose_lines.append("=" * 80)
            verbose_lines.append("COMPREHENSIVE AUDIT SUMMARY")
            verbose_lines.append("=" * 80)
            verbose_lines.append("")
            
            # Group findings by severity
            critical_findings = [f for f in result['findings'] if f.get('severity') == 'CRITICAL']
            warning_findings = [f for f in result['findings'] if f.get('severity') == 'WARNING']
            info_findings = [f for f in result['findings'] if f.get('severity') == 'INFO']
            
            # Critical issues
            if critical_findings:
                verbose_lines.append(f"[!] CRITICAL ISSUES ({len(critical_findings)}):")
                for finding in critical_findings:
                    title = finding.get('title', 'Unknown Issue')
                    desc = finding.get('description', 'No description')
                    verbose_lines.append(f"  - {title}: {desc}")
                verbose_lines.append("")
            
            # Warnings
            if warning_findings:
                verbose_lines.append(f"[*] WARNINGS ({len(warning_findings)}):")
                for finding in warning_findings:
                    title = finding.get('title', 'Unknown Issue')
                    desc = finding.get('description', 'No description')
                    verbose_lines.append(f"  - {title}: {desc}")
                verbose_lines.append("")
            
            # Informational
            if info_findings:
                verbose_lines.append(f"[i] INFORMATIONAL ({len(info_findings)}):")
                for finding in info_findings:
                    title = finding.get('title', 'Unknown Issue')
                    desc = finding.get('description', 'No description')
                    verbose_lines.append(f"  - {title}: {desc}")
                verbose_lines.append("")
            
            # Findings by category
            verbose_lines.append("-" * 80)
            verbose_lines.append("FINDINGS BY CATEGORY:")
            
            # Group by category
            categories = {}
            for finding in result['findings']:
                category = finding.get('category', 'General')
                if category not in categories:
                    categories[category] = 0
                categories[category] += 1
            
            for category, count in sorted(categories.items()):
                verbose_lines.append(f"  {category}: {count} finding(s)")
            
            verbose_lines.append("")
            verbose_lines.append("=" * 80)
        
        # Add product type detection
        product_type = result.get('product', 'unknown').lower()
        verbose_lines.append(f"[INFO] Detected policy type: {product_type}")
        
        return html.escape('\n'.join(verbose_lines))
    
    def _format_xml_for_display(self, xml_content: str) -> str:
        """Format XML content for HTML display"""
        import html
        if isinstance(xml_content, dict):
            # Convert dict back to XML-like string for display
            import json
            return html.escape(json.dumps(xml_content, indent=2))
        elif isinstance(xml_content, str):
            return html.escape(xml_content)
        else:
            return html.escape(str(xml_content))
    
    def _generate_csv_report(self, result: Dict[str, Any], output_dir: Path):
        """Generate CSV report for a policy"""
        csv_file = output_dir / 'audit_findings.csv'
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Policy Name', 'Policy GUID', 'Severity', 'Category', 
                'Title', 'Description', 'Recommendation', 'Timestamp'
            ])
            
            for finding in result['findings']:
                writer.writerow([
                    result['name'],
                    result['guid'],
                    finding.get('severity', ''),
                    finding.get('category', ''),
                    finding.get('title', ''),
                    finding.get('description', ''),
                    finding.get('recommendation', ''),
                    finding.get('timestamp', '')
                ])
    
    def _generate_findings_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Generate summary statistics for findings"""
        summary = {'critical': 0, 'warning': 0, 'info': 0, 'total': len(findings)}
        
        for finding in findings:
            severity = finding.get('severity', 'INFO').lower()
            if severity == 'critical':
                summary['critical'] += 1
            elif severity == 'warning':
                summary['warning'] += 1
            else:
                summary['info'] += 1
        
        return summary
    
    def _generate_summary_reports(self):
        """Generate overall summary reports"""
        print(f"\n[+] Generating summary reports in {self.output_dir}")
        
        # Calculate overall statistics
        total_policies = len(self.audit_results)
        total_critical = sum(len([f for f in r['findings'] if f.get('severity') == 'CRITICAL']) for r in self.audit_results.values())
        total_warnings = sum(len([f for f in r['findings'] if f.get('severity') == 'WARNING']) for r in self.audit_results.values())
        total_info = sum(len([f for f in r['findings'] if f.get('severity') == 'INFO']) for r in self.audit_results.values())
        
        # Print summary
        print("\n" + "="*80)
        print("COMPREHENSIVE AUDIT SUMMARY")
        print("="*80)
        print(f"Total Policies Audited: {total_policies}")
        print(f"[!] Total Critical Issues: {total_critical}")
        print(f"[*] Total Warnings: {total_warnings}")
        print(f"[i] Total Informational: {total_info}")
        print(f"\n[+] Per-policy reports generated in: {self.output_dir / 'policies'}")
        
        # Generate master summary in requested formats
        if 'json' in self.formats:
            self._generate_master_json_summary()
        
        if 'html' in self.formats:
            self._generate_master_html_summary()
        
        if 'csv' in self.formats:
            self._generate_master_csv_summary()
    
    def _generate_master_json_summary(self):
        """Generate master JSON summary"""
        summary_data = {
            'audit_metadata': {
                'timestamp': datetime.datetime.now().isoformat(),
                'total_policies': len(self.audit_results),
                'auditor_version': '2.0',
                'api_endpoint': self.config.get('api', 'domainIP')
            },
            'overall_statistics': {
                'critical_issues': sum(len([f for f in r['findings'] if f.get('severity') == 'CRITICAL']) for r in self.audit_results.values()),
                'warnings': sum(len([f for f in r['findings'] if f.get('severity') == 'WARNING']) for r in self.audit_results.values()),
                'informational': sum(len([f for f in r['findings'] if f.get('severity') == 'INFO']) for r in self.audit_results.values())
            },
            'policy_summaries': {
                guid: {
                    'name': result['name'],
                    'product': result['product'],
                    'findings_count': len(result['findings']),
                    'severity_breakdown': self._generate_findings_summary(result['findings'])
                }
                for guid, result in self.audit_results.items()
            }
        }
        
        with open(self.output_dir / 'master_summary.json', 'w') as f:
            json.dump(summary_data, f, indent=2)
    
    def _generate_master_html_summary(self):
        """Generate master HTML summary"""
        # This would be a comprehensive HTML dashboard
        # Implementation similar to individual HTML reports but with overview
        pass
    
    def _generate_master_csv_summary(self):
        """Generate master CSV summary"""
        with open(self.output_dir / 'all_findings.csv', 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Policy Name', 'Policy GUID', 'Product', 'Severity', 'Category',
                'Title', 'Description', 'Recommendation', 'Timestamp'
            ])
            
            for result in self.audit_results.values():
                for finding in result['findings']:
                    writer.writerow([
                        result['name'],
                        result['guid'],
                        result['product'],
                        finding.get('severity', ''),
                        finding.get('category', ''),
                        finding.get('title', ''),
                        finding.get('description', ''),
                        finding.get('recommendation', ''),
                        finding.get('timestamp', '')
                    ])


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
        description="Cisco Secure Endpoint Comprehensive Policy Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -c config.txt -o audit_results/
  %(prog)s -c config.txt -o audit_results/ --formats json html csv
  %(prog)s -c config.txt -o audit_results/ --formats html --verbose
        """
    )
    
    parser.add_argument(
        "-c", "--config",
        dest="config_path",
        required=True,
        help="Path to configuration file",
        type=validate_file,
        metavar="FILE"
    )
    
    parser.add_argument(
        "-o", "--output",
        dest="output_dir",
        required=True,
        help="Output directory for audit reports",
        type=validate_directory,
        metavar="DIR"
    )
    
    parser.add_argument(
        "--formats",
        nargs='+',
        choices=['json', 'html', 'csv'],
        default=['json', 'html'],
        help="Output formats (default: json html)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        auditor = ComprehensivePolicyAuditor(args.config_path, args.output_dir, args.formats)
        
        if not auditor.fetch_policies():
            logger.error("Failed to fetch policies from API")
            sys.exit(1)
            
        auditor.audit_all_policies()
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()