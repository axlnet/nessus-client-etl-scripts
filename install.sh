#!/bin/bash

# Set variables
REPO_URL="https://github.com/axlnet/nessus-client-etl-scripts.git"
INSTALL_DIR="/opt/nessus-client-etl-scripts"
CONFIG_FILE="config.ini"
REQUIREMENTS_FILE="requirements.txt"
VENV_DIR=".venv"
LOG_DIR="/var/log"
LOG_FILE="axlnet-nessus-scanner.log"
CRONTAB_CMD="cd $INSTALL_DIR && ./$VENV_DIR/bin/python3 export.py >> $LOG_DIR/$LOG_FILE 2>&1"
CRONTAB_SCHEDULE="1 0 * * *"
# Script info
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
SCRIPT_NAME=$(basename "$0")

# Define your secrets here
HOSTNAME="localhost"
PORT="8834"
ACCESS_KEY=""
SECRET_KEY=""
AWS_USER_ID=""
AWS_USER_SECRET=""
AWS_REGION="us-east-1"
AWS_S3_BUCKET="prod-axlnet-nessus-ingestion"

# Generate a random UUID for deployment_id
apt install uuid-runtime
DEPLOYMENT_ID=$(uuidgen)
echo "Generated deployment_id: $DEPLOYMENT_ID"

# Clone the repository using the PAT
git clone $REPO_URL $INSTALL_DIR

# Navigate to the install directory
cd $INSTALL_DIR

# Create the config.ini file
cat <<EOL > $CONFIG_FILE
[nessus]
hostname=$HOSTNAME
port=$PORT
access_key=$ACCESS_KEY
secret_key=$SECRET_KEY

[aws]
aws_nessus_scanner_user_id=$AWS_USER_ID
aws_nessus_scanner_user_secret=$AWS_USER_SECRET
aws_region=$AWS_REGION
aws_s3_bucket_name=$AWS_S3_BUCKET

[scanner]
deployment_id=$DEPLOYMENT_ID
EOL

apt install python3.11-venv

# Create a virtual environment
python3 -m venv $VENV_DIR

# Activate the virtual environment and install Python dependencies
source $VENV_DIR/bin/activate
pip3 install -r $REQUIREMENTS_FILE
deactivate

# Create log directory if it doesn't exist
mkdir -p $LOG_DIR

# Add the script to crontab
(crontab -l 2>/dev/null; echo ""; echo "# Import new Nessus scans - Daily at 12:01 AM"; echo "$CRONTAB_SCHEDULE $CRONTAB_CMD") | crontab -

# Your message will self-destruct in 30 seconds.
rm -- "$SCRIPT_DIR/$SCRIPT_NAME"