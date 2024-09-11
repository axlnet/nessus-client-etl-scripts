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
FOLDERS = '/folders'
SCANS = '/scans'

SCAN_ID = SCANS + '/{scan_id}'
HOST_ID = SCAN_ID + '/hosts/{host_id}'
PLUGIN_ID = HOST_ID + '/plugins/{plugin_id}'

SCAN_RUN = SCAN_ID + '?history_id={history_id}'
HOST_VULN = HOST_ID + '?history_id={history_id}'
PLUGIN_OUTPUT = PLUGIN_ID + '?history_id={history_id}'

# ---Functions---
# Utils
def current_date_folder_name():
    current_date = datetime.now()
    # Format date as YYYYMMDD
    return current_date.strftime('%Y%m%d')

def calculate_severities(target):
    sev_count = [0] * 5
    for vuln in target.get('vulnerabilities', []):
        if vuln.get('severity'):
            sev_count[vuln['severity']] += vuln['count']
    return sev_count

# S3 functions
s3_client = boto3.client(
    's3',
    aws_access_key_id=aws_nessus_scanner_user_id,
    aws_secret_access_key=aws_nessus_scanner_user_secret,
    region_name=aws_region
)

def get_latest_folder():
    paginator = s3_client.get_paginator('list_objects_v2')
    
    folder_dates = []
    # Pagination
    for page in paginator.paginate(Bucket=aws_s3_bucket_name, Prefix=f"{deployment_id}/"):
        folder_dates.extend([
            datetime.strptime(obj['Key'].split('/')[1], '%Y%m%d')
            for obj in page.get('Contents', [])
            if len(obj['Key'].split('/')) > 1 and obj['Key'].split('/')[1].isdigit() and len(obj['Key'].split('/')[1]) == 8
        ])
    # Newest folder in bucket OR from the start of epoch time
    return max(folder_dates) if folder_dates else datetime(1970, 1, 1)

def upload_data_to_s3(data, file_type):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """
    file_name = f"{deployment_id}/{current_date_folder_name()}/{file_type}.json"
    # Upload the file
    try:
        # Convert to json
        json_data = json.dumps(data)
        with ThreadPoolExecutor() as executor:
            executor.submit(s3_client.put_object, Body=json_data, Bucket=aws_s3_bucket_name, Key=file_name)
    except Exception as e:
        print(e)
        return False
        # TODO: LOG THIS WITH DATADOG!!!
    return True

# Nessus API functions
def request(url):
    url = base + url
    headers = {'X-ApiKeys': access_key + secret_key}
    response = requests.get(url=url,headers=headers,verify=False)
    return response.json()

def get_folders():
    return request(FOLDERS)

def get_scans():
    return request(SCANS)

def get_scan(scan_id):
    return request(SCAN_ID.format(scan_id=scan_id))

def get_scan_run(scan_id, history_id):
    return request(SCAN_RUN.format(scan_id=scan_id, history_id=history_id))

def get_host_vuln(scan_id, host_id, history_id):
    return request(HOST_VULN.format(scan_id=scan_id, host_id=host_id, history_id=history_id))

def get_plugin_output(scan_id, host_id, plugin_id, history_id):
    return request(PLUGIN_OUTPUT.format(scan_id=scan_id, host_id=host_id, plugin_id=plugin_id, history_id=history_id))

# Nessus export functions
def format_plugin(plugin):
    # Split references array into string delimited by new line
    reference = None
    if plugin['pluginattributes'].get('see_also', None) != None:
        reference = '\n'.join(plugin['pluginattributes'].get('see_also', None))
    plugin['ref'] = reference
    return plugin

def format_vuln_outputs(vuln_output):
    outputs = []
    for output in vuln_output:
        for port in output['ports'].keys():
            outputs.append({'port': port, 'output': output['plugin_output']})
    return outputs

def format_host_vuln(scan_id, host_id, plugin_id, history_id):
    # Need to insert plugin first to have FK relationship
    # Get vuln output which includes plugin info
    vuln_output = get_plugin_output(scan_id, host_id, plugin_id, history_id)
    plugin = format_plugin(vuln_output['info']['plugindescription'])

    # Insert host vuln
    host_vuln = {'nessus_host_id': host_id, 'scan_run_id': history_id, 'plugin_id': plugin_id}
    # Finally format vuln output and upload
    outputs = format_vuln_outputs(vuln_output['outputs'])
    return {'plugin': plugin, 'host_vuln': host_vuln, 'outputs': outputs}

def format_host(scan_id, host_id, history_id):
    # Get host vulnerabilities for a scan run
    host = get_host_vuln(scan_id, host_id, history_id) 
    print("        Host vulnerabilities pulled")

    # Count number of vulns of each severity for this host in this scan run
    # 0 is informational, 4 is critical
    sev_count = calculate_severities(host)

    host['host_id'] = host_id
    host['history_id'] = history_id
    host['scan_id'] = scan_id
    host['critical_count'] = sev_count[4]
    host['high_count'] = sev_count[3]
    host['medium_count'] = sev_count[2]
    host['low_count'] = sev_count[1]
    host['info_count'] = sev_count[0]

    # Format host vulnerabilities
    with ThreadPoolExecutor() as executor:
        host['vulnerabilities'] = list(executor.map(lambda vuln: format_host_vuln(scan_id, host_id, vuln['plugin_id'], history_id), host['vulnerabilities']))
    print(f"            {len(host['vulnerabilities'])} vulnerabilities' plugins pulled and formatted")
    
    return host

def insert_scan_run(scan_id, history_id):
    # Get scan runs for a scan
    scan_run = get_scan_run(scan_id, history_id)
    print("    Scan run pulled from Nessus")
    # Count number of vulns of each severity for this scan run
    # 0 is informational, 4 is critical
    sev_count = calculate_severities(scan_run)

    scan_summary = {
        'history_id': history_id,
        'scan_id': scan_id,
        'scanner_start': scan_run['info']['scan_start'],
        'scanner_end': scan_run['info']['scan_end'],
        'targets': scan_run['hosts'],
        'host_count': scan_run['info']['hostcount'],
        'critical_count': sev_count[4],
        'high_count': sev_count[3],
        'medium_count': sev_count[2],
        'low_count': sev_count[1],
        'info_count': sev_count[0],
    }

    # Format hosts in scan run
    for i in range(len(scan_run['hosts'])):
        scan_run['hosts'][i] = format_host(scan_id, scan_run['hosts'][i]['host_id'], history_id)
        print("    Hosts formatted")

    upload_data_to_s3(scan_summary, f"scan_run_{scan_id}_{history_id}")
    print("    Data uploaded to S3")

latest_folder_date = get_latest_folder().date()
print(f"Pulling all scans since {latest_folder_date}")

def update_scans():
    scan_runs_exist = False
    scans = get_scans()

    for scan in scans['scans']:
        print ('Processing: ' + scan['name'])
        
        # Retreive details about the current scan
        scan_details = get_scan(scan['id'])

        if scan_details['history'] != None:
            # Check each run of each scan
            for scan_run in scan_details['history']:
                # Only import if scan finished completely
                if scan_run['status'] == 'completed' and datetime.fromtimestamp(scan_run['last_modification_date']).date() >= latest_folder_date:
                    print ('Inserting scan run: ' + str(scan_run['history_id']))
                    insert_scan_run(scan['id'], scan_run['history_id'])
                    scan_runs_exist = True
    
    if scan_runs_exist:
        folders = get_folders()
        upload_data_to_s3(folders, 'folder')
        upload_data_to_s3(scans, 'scan')



update_scans()

"""
TODO: (before release to client endpoints)
* Logging
* LOTS of try catches and other error protection
* Test output validity (can it be ingested)
"""