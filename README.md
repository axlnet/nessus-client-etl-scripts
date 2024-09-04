# Axl.net Internal Nessus Scanner ETL Tool
A script to export Nessus results regularly into an AWS bucket for easy analysis/aggregation.

## Install
1. Use [this document](https://docs.google.com/spreadsheets/d/1DiAgFYb_Y1e50SUAb-VvOQoyF5z0Mvwa0k6QXUU7srs/edit?gid=1161236586#gid=1161236586) to keep track of clients' internal Nessus scanners
2. Ssh into the desired scanner
3. `nano install.sh`
4. Paste in the contents of `install.sh` in this repo
5. Fill in the following parameters in the script:
    * ACCESS_KEY=""
    * SECRET_KEY=""
    * AWS_USER_ID=""
    * AWS_USER_SECRET=""
>AWS_USER_ID and SECRET can be found in the prod account. ACCESS_KEY and SECRET_KEY are specific to that Nessus installation. Nessus API access credentials must be made from that machine's GUI.
6. `sudo bash install.sh`
7. The script should print a uuid at some point (ex: dddb0f5c-0caa-449d-9ddf-6bf50ddd45cd). Copy it and use it to create a new row in the `nessusdb2.scaner_deployments` table.

| scaner_deployment_id | client_id | Location            | deployment_uuid                      | scanner_type | hardware |
|----------------------|-----------|---------------------|--------------------------------------|--------------|----------|
|                  Eg. |       Eg. | From above document | dddb0f5c-0caa-449d-9ddf-6bf50ddd45cd | internal     | From doc |

# Usage
From the root directory of the repo (try `/opt/nessus-client-etl-scripts/` or `/opt/scheduled-tasks/nessus-client-etl-scripts/`):
1. `source .venv/bin/activate`
2. `python3 export.py`
