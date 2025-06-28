#!/usr/bin/env python3
"""
Cisco Secure Endpoint Policy Downloader
Downloads all policies from the API in XML format

Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file in this repository
GitHub: https://github.com/op7ic/amp-policy-kit
"""

import sys
import requests
import configparser
import argparse
import logging
import json
from pathlib import Path
from typing import Dict, Any, List
import concurrent.futures
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class PolicyDownloader:
    """Downloads policies from Cisco Secure Endpoint API"""
    
    def __init__(self, config_path: str, output_dir: str, skip_html: bool = False):
        self.config = self._load_config(config_path)
        self.output_dir = Path(output_dir)
        self.session = self._create_session()
        self.skip_html = skip_html
        
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def _load_config(self, config_path: str) -> configparser.ConfigParser:
        """Load configuration from file"""
        config = configparser.ConfigParser()
        if not config.read(config_path):
            raise ValueError(f"Failed to read config file: {config_path}")
            
        # Validate required settings
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
            'User-Agent': 'AMP-Policy-Downloader/2.0'
        })
        return session
    
    def fetch_policies_list(self) -> List[Dict[str, Any]]:
        """Fetch list of all policies"""
        try:
            base_url = f"https://{self.config.get('api', 'domainIP')}/v1/policies"
            
            logger.info("Fetching policy list from API...")
            
            all_policies = []
            offset = 0
            limit = 500  # API limit
            
            while True:
                params = {'offset': offset, 'limit': limit}
                response = self.session.get(base_url, params=params)
                response.raise_for_status()
                
                data = response.json()
                policies = data.get('data', [])
                all_policies.extend(policies)
                
                # Check if there are more pages
                metadata = data.get('metadata', {})
                total = metadata.get('results', {}).get('total', 0)
                
                if offset + limit >= total:
                    break
                    
                offset += limit
            
            logger.info(f"Found {len(all_policies)} policies")
            return all_policies
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch policies: {e}")
            return []
    
    def download_policy(self, policy: Dict[str, Any]) -> bool:
        """Download a single policy XML"""
        try:
            policy_name = policy.get('name', 'Unknown')
            policy_guid = policy.get('guid', 'unknown')
            policy_product = policy.get('product', 'unknown')
            
            # Create safe filename
            safe_name = "".join(c for c in policy_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
            safe_product = "".join(c for c in policy_product if c.isalnum() or c in (' ', '-', '_')).rstrip()
            
            # Include serial number if available
            serial = policy.get('serial_number', '')
            if serial:
                filename = f"{safe_name}_{safe_product}_serialnumber{serial}.xml"
            else:
                filename = f"{safe_name}_{safe_product}_{policy_guid}.xml"
            
            filepath = self.output_dir / filename
            
            # Check if already downloaded
            if filepath.exists():
                logger.debug(f"Policy already exists: {filename}")
                return True
            
            # Download XML
            xml_url = f"https://{self.config.get('api', 'domainIP')}/v1/policies/{policy_guid}.xml"
            response = self.session.get(xml_url)
            response.raise_for_status()
            
            # Save to file
            filepath.write_text(response.text, encoding='utf-8')
            logger.info(f"Downloaded: {filename}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to download policy {policy.get('name', 'Unknown')}: {e}")
            return False
    
    def download_all_policies(self):
        """Download all policies in parallel"""
        policies = self.fetch_policies_list()
        
        if not policies:
            logger.warning("No policies found to download")
            return
        
        print(f"\nDownloading {len(policies)} policies to {self.output_dir}")
        
        # Create metadata file
        metadata = {
            'download_timestamp': datetime.now().isoformat(),
            'total_policies': len(policies),
            'api_endpoint': self.config.get('api', 'domainIP'),
            'policies': []
        }
        
        # Download policies in parallel
        successful = 0
        failed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_policy = {
                executor.submit(self.download_policy, policy): policy 
                for policy in policies
            }
            
            for future in concurrent.futures.as_completed(future_to_policy):
                policy = future_to_policy[future]
                try:
                    if future.result():
                        successful += 1
                        metadata['policies'].append({
                            'name': policy.get('name'),
                            'guid': policy.get('guid'),
                            'product': policy.get('product'),
                            'serial_number': policy.get('serial_number'),
                            'modified_at': policy.get('modified_at')
                        })
                    else:
                        failed += 1
                except Exception as e:
                    logger.error(f"Error downloading policy: {e}")
                    failed += 1
        
        # Save metadata
        metadata_file = self.output_dir / 'download_metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Print summary
        print("\n" + "="*60)
        print("DOWNLOAD SUMMARY")
        print("="*60)
        print(f"[+] Successfully downloaded: {successful}")
        if failed > 0:
            print(f"[-] Failed downloads: {failed}")
        print(f"[+] Output directory: {self.output_dir}")
        print(f"[+] Metadata saved to: {metadata_file}")
        
        # Create index file
        if not self.skip_html:
            try:
                self._create_index_file()
            except Exception as e:
                logger.warning(f"Failed to create HTML index: {e}")
                logger.info("You can still access policies directly from the output directory")
    
    def _create_index_file(self):
        """Create an index HTML file for easy navigation"""
        index_path = self.output_dir / 'index.html'
        
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Cisco Secure Endpoint Policies</title>
    <style>
        body { margin: 20px; }
        h1 { color: #0066cc; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .timestamp { color: #666; }
        .product { font-weight: bold; }
        .windows { color: #0078d4; }
        .mac { color: #555555; }
        .linux { color: #dd4814; }
        .android { color: #3ddc84; }
        .ios { color: #007aff; }
        .network { color: #6f42c1; }
    </style>
</head>
<body>
    <h1>Cisco Secure Endpoint Policies</h1>
    <p class="timestamp">Generated: {timestamp}</p>
    
    <table>
        <tr>
            <th>Policy Name</th>
            <th>Product</th>
            <th>File</th>
            <th>Modified</th>
        </tr>
"""
        
        # Load metadata
        metadata_file = self.output_dir / 'download_metadata.json'
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
                
            for policy in metadata.get('policies', []):
                product = policy.get('product', 'unknown').lower()
                product_class = product.split()[0] if product else 'unknown'
                
                # Find corresponding file
                files = list(self.output_dir.glob(f"*{policy['guid']}*.xml"))
                if not files:
                    # Try with serial number
                    serial = policy.get('serial_number')
                    if serial:
                        files = list(self.output_dir.glob(f"*serialnumber{serial}.xml"))
                
                if files:
                    filename = files[0].name
                    
                    html_content += f"""
        <tr>
            <td>{policy['name']}</td>
            <td class="product {product_class}">{policy['product']}</td>
            <td><a href="{filename}">{filename}</a></td>
            <td>{policy.get('modified_at', 'Unknown')}</td>
        </tr>
"""
        
        html_content += """
    </table>
</body>
</html>
"""
        
        html_content = html_content.format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        with open(index_path, 'w') as f:
            f.write(html_content)
            
        logger.info(f"Created index file: {index_path}")


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
        description="Cisco Secure Endpoint Policy Downloader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Configuration file format:
  [api]
  client_id = your_client_id
  api_key = your_api_key
  domainIP = api.amp.cisco.com

Available endpoints:
  - api.eu.amp.cisco.com (Europe)
  - api.amp.cisco.com (Americas)
  - api.apjc.amp.cisco.com (Asia Pacific)

Examples:
  %(prog)s -c config.txt -o policies/
  %(prog)s --config /path/to/config.txt --output /tmp/amp-policies
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
        help="Output directory for policy XML files",
        type=validate_directory,
        metavar="DIR"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip HTML index generation"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        # Create downloader and download policies
        downloader = PolicyDownloader(args.config_path, args.output_dir, skip_html=args.no_html)
        downloader.download_all_policies()
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()