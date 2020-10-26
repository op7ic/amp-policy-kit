#####################################################################################
# IMPORTS
#####################################################################################
import sys
import requests
import configparser
import time
import datetime
import dateutil
import gc
import json
from urllib.parse import urlparse
import argparse
import os
from xml.etree.ElementTree import fromstring, ElementTree,tostring

try:
	# Used for parsing XML files to make them formatted a bit better
    from bs4 import BeautifulSoup                  
except ImportError:
	print("[!] You do not appear to have 'BeautifulSoup' installed" )
	print("[!] Please execute 'pip3 install beautifulsoup4' command. Exiting")
	sys.exit(0)

#####################################################################################
# HELPERS
#####################################################################################

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Ensure that file path is actually valid, to be used by ArgumentParser 'type' option
def validate_file(f):
    if not os.path.exists(f):
    	# Raise exception if specified path does not exist
        raise argparse.ArgumentTypeError("Path {0} does not exist".format(f))
    return f

#####################################################################################
# MAIN
#####################################################################################
def main():
	# Parse arguments
	ap = argparse.ArgumentParser()
	ap.add_argument("-c", "--config", dest="config_path", required=True, help="path to config file", type=validate_file, metavar="FILE")
	ap.add_argument("-o", "--output", dest="outout_folder", required=True, help="path to output folder", type=validate_file)
	args = ap.parse_args()

	# Parse config to extract API keys
	config = configparser.ConfigParser()
	config.read(args.config_path)
	client_id = config['settings']['client_id']
	api_key = config['settings']['api_key']
	domainIP = config['settings']['domainIP']

	try:
	    # http://docs.python-requests.org/en/master/user/advanced/
	    # Using a session object gains efficiency when making multiple requests
	    session = requests.Session()
	    session.auth = (client_id, api_key)

	    # Define URL for extraction of all policies
	    policy_url='https://{}/v1/policies'.format(domainIP)
	    response = session.get(policy_url, verify=False)
	    # Get Headers
	    headers=response.headers
	    # Decode JSON response
	    response_json = response.json()
	    print("[+] Total number of policies: {}".format(response_json['metadata']['results']['total']))
	    policies = response_json['data']
	    # Enumerate all policies and download them to specified folder
	    for policy_detail in policies:
	    	policy_url='https://{}/v1/policies/{}'.format(domainIP,policy_detail['guid'])
	    	# Reuse session, get XML out
	    	response = session.get(policy_url, verify=False)
	    	headers=response.headers
	    	# Parse out response as JSON so we can extract at least basic metadata which can be used for further processing
	    	response_json = response.json()
	    	# Print out basic details about policy
	    	print("[+] Downloading Policy. NAME: {} GUID: {} PRODUCT: {}  DEFAULT: {} SERIAL NUMBER: {} URL: {}".format(policy_detail['name'],policy_detail['guid'],policy_detail['product'],policy_detail['default'],policy_detail['serial_number'],policy_detail['links']['policy']))
    		policy_url='https://{}/v1/policies/{}.xml'.format(domainIP,policy_detail['guid'])
    		# Final request - get policy XML file, parse and write to file
    		response = session.get(policy_url, verify=False)
    		#Parse and prettify XML file before writing
    		tree = ElementTree(fromstring(response.content))
    		# Get Root of XML policy file
    		root = tree.getroot()
    		b4_xml_obj = BeautifulSoup(tostring(root), "xml")
    		# Construct path for writing out policy as XML file
    		filename = os.path.join(args.outout_folder,"{}_{}.xml".format(policy_detail['guid'],policy_detail['product']))
    		f = open(filename, "w")
    		# Write out file to disk, prettified
    		f.write(b4_xml_obj.prettify())
    		# Close stream
    		f.close()
	finally:
		print("[+] Done")
		gc.collect()

if __name__ == "__main__":
    main()