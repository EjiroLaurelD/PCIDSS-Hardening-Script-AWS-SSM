#!/bin/bash
# setup-ssm-association.sh
# Creates an SSM State Manager association to ensure all EC2 instances meet PCI DSS requirements

# Variables
AWS_REGION="eu-west-2"  # Change to your region
WAZUH_MANAGER_IP="12.34.56.78"  # Change to your Wazuh manager IP
ASSOCIATION_NAME="PCIDSSHardeningAssociation"
DOCUMENT_NAME="PCI-DSS-Hardening"

# Create the association using State Manager
aws ssm create-association \
  --name $DOCUMENT_NAME \
  --association-name $ASSOCIATION_NAME \
  --targets "Key=instanceids,Values=*" \
  --parameters "wazuhManagerIP=$WAZUH_MANAGER_IP" \
  --schedule-expression "cron(0 2 * * ? *)" \
  --apply-only-at-cron-interval \
  --max-errors "10%" \
  --max-concurrency "10%" \
  --compliance-severity "HIGH" \
  --region $AWS_REGION

echo "SSM State Manager association '$ASSOCIATION_NAME' created."
echo "The PCI DSS hardening will run daily at 2 AM UTC on all EC2 instances."
echo "New instances will automatically receive the hardening when they start."
