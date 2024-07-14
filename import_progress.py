#!/usr/bin/env python3
import configparser
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
import os
import boto3
from botocore.exceptions import ClientError
import datadog
import json
from datetime import datetime

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Read configuration
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))
# Nessus config vars
nessus_hostname = config.get('nessus','hostname')
nessus_port = config.get('nessus','port')
nessus_access_key = config.get('nessus','access_key')
nessus_secret_key = config.get('nessus','secret_key')
access_key = 'accessKey=' + nessus_access_key + ';'
secret_key = 'secretKey=' + nessus_secret_key + ';'
base = 'https://{hostname}:{port}'.format(hostname=nessus_hostname, port=nessus_port)
# AWS config vars
aws_nessus_scanner_user_id = config.get('aws', 'aws_nessus_scanner_user_id')
aws_nessus_scanner_user_secret = config.get('aws', 'aws_nessus_scanner_user_secret')
aws_region = config.get('aws', 'aws_region')
aws_s3_bucket_name = config.get('aws', 'aws_s3_bucket_name')
# Scanner config vars
deployment_id = config.get('scanner', 'deployment_id')

# Check for missing config vars
if not all([nessus_hostname, nessus_port, nessus_access_key, nessus_secret_key, 
            aws_nessus_scanner_user_id, aws_nessus_scanner_user_secret, 
            aws_region, aws_s3_bucket_name, deployment_id]):
    raise ValueError("Missing one or more config vars.")

# Nessus endpoints
SCANS = '/scans'

# ---Functions---
# Utils

# S3 functions
s3_client = boto3.client(
    's3',
    aws_access_key_id=aws_nessus_scanner_user_id,
    aws_secret_access_key=aws_nessus_scanner_user_secret,
    region_name=aws_region
)

# Nessus API functions
def request(url):
    url = base + url
    headers = {'X-ApiKeys': access_key + secret_key}
    response = requests.get(url=url, headers=headers, verify=False)
    return response.json()

def get_scans():
    return request(SCANS)

existing_scans = set()

def count_existing_scans():
    paginator = s3_client.get_paginator('list_objects_v2')
    
    # Iterate through each date folder within the deployment_id folder
    for page in paginator.paginate(Bucket=aws_s3_bucket_name, Prefix=f"{deployment_id}/"):
        for obj in page.get('Contents', []):
            key_parts = obj['Key'].split('/')
            # Check if the key corresponds to a file within a date-named folder
            if key_parts[2].startswith('scan_run_'):
                scan_id = key_parts[2].split('_')[2]
                existing_scans.add(scan_id)
    return existing_scans

def count_scans():
    scans = get_scans()
    
    total_scans = 0
    new_scans_count = 0
    existing_scans = count_existing_scans()

    for scan in scans['scans']:
        total_scans += 1
        if scan['id'] not in existing_scans:
            new_scans_count += 1

    print(f"Total scans found: {total_scans}")
    print(f"Scans left to import: {new_scans_count}")

existing_scans_count = count_existing_scans()
print(f"Total existing scans in folder: {len(existing_scans_count)}")

count_scans()