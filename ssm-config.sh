#!/bin/bash
# pci-hardening-ssm.sh
# Script to apply PCI DSS hardening directly via AWS SSM Run Command

# Configuration - modify these variables
INSTANCE_IDS="i-038b2545..." # Replace with your actual instance IDs
WAZUH_MANAGER_IP="12.34.56.78" # Replace with your actual Wazuh manager IP
AWS_REGION="eu-west-2" # Replace with your AWS region
DRY_RUN="FALSE" #use dry run "true" to test the configuration then change to false when you're okay with your configuration

# Create a temporary SSM document for PCI DSS hardening
echo "Creating SSM document for PCI DSS hardening..."
cat > pci-dss-hardening.json << 'EOF'
{
  "schemaVersion": "2.2",
  "description": "PCI DSS Hardening with Wazuh and ClamAV",
  "parameters": {
    "wazuhManagerIP": {
      "type": "String",
      "default": "WAZUH_MANAGER_IP_PLACEHOLDER",
      "description": "Wazuh Manager IP address"
    }
  },
  "mainSteps": [
    {
      "action": "aws:runShellScript",
      "name": "InstallSecurityPackages",
      "inputs": {
        "runCommand": [
          "#!/bin/bash",
          "echo 'Installing security packages...'",
          "yum update -y",
          "yum install -y aide fail2ban auditd rsyslog cronie policycoreutils",
          "echo 'Security packages installed.'"
        ]
      }
    },
    {
      "action": "aws:runShellScript",
      "name": "ConfigureSSH",
      "inputs": {
        "runCommand": [
          "#!/bin/bash",
          "echo 'Configuring SSH hardening...'",
          "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
          "sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config",
          "sed -i 's/^#\\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config",
          "sed -i 's/^#\\?MaxAuthTries.*/MaxAuthTries 5/' /etc/ssh/sshd_config",
          "sed -i 's/^#\\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config",
          "sed -i 's/^#\\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config",
          "sed -i 's/^#\\?ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config",
          "systemctl restart sshd",
          "echo 'SSH hardening complete.'"
        ]
      }
    },
    {
      "action": "aws:runShellScript",
      "name": "ConfigurePasswordPolicy",
      "inputs": {
        "runCommand": [
          "#!/bin/bash",
          "echo 'Configuring password policies...'",
          "# Install password quality packages",
          "yum install -y libpwquality pam",
          "# Configure strong password policy with 12 char minimum",
          "cat > /etc/security/pwquality.conf << 'EOL'",
          "# Password quality configuration for PCI DSS compliance",
          "# Minimum password length of 12 characters",
          "minlen = 12",
          "# Require at least one digit",
          "dcredit = -1",
          "# Require at least one uppercase letter",
          "ucredit = -1",
          "# Require at least one lowercase letter",
          "lcredit = -1",
          "# Require at least one special character",
          "ocredit = -1",
          "# Only allow 3 consecutive identical characters",
          "maxrepeat = 3",
          "# Enforce retry limit",
          "retry = 3",
          "# Enforce minimum difference between old and new password",
          "difok = 3",
          "EOL",
          "# Set password aging",
          "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs",
          "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs",
          "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs",
          "echo 'Password policies configured.'"
        ]
      }
    },
    {
      "action": "aws:runShellScript",
      "name": "SetFilePermissions",
      "inputs": {
        "runCommand": [
          "#!/bin/bash",
          "echo 'Setting critical file permissions...'",
          "chmod 644 /etc/passwd",
          "chmod 000 /etc/shadow",
          "chmod 000 /etc/gshadow",
          "chmod 644 /etc/group",
          "chown root:root /etc/passwd /etc/shadow /etc/gshadow /etc/group",
          "echo 'File permissions set.'"
        ]
      }
    },
    {
      "action": "aws:runShellScript",
      "name": "InstallClamAV",
      "inputs": {
        "runCommand": [
          "#!/bin/bash",
          "echo 'Installing ClamAV...'",
          "yum install -y clamav clamav-update",
          "freshclam || echo 'Freshclam update attempted'",
          "echo '0 3 * * * /usr/bin/freshclam > /dev/null 2>&1' | crontab -",
          "echo '0 2 * * * /usr/bin/clamscan -r / --exclude-dir=^/sys|^/proc|^/dev --log=/var/log/clamav_scan.log' | crontab -",
          "echo 'ClamAV installed and configured.'"
        ]
      }
    },
    {
      "action": "aws:runShellScript",
      "name": "InstallWazuhAgent",
      "inputs": {
        "runCommand": [
          "#!/bin/bash",
          "echo 'Installing Wazuh agent...'",
          "curl -o wazuh-agent-4.9.2-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.2-1.x86_64.rpm",
          "sudo WAZUH_MANAGER='{{wazuhManagerIP}}' rpm -ihv wazuh-agent-4.9.2-1.x86_64.rpm || echo 'Wazuh agent installation attempted'",
          "sed -i \"s/<address>.*<\\/address>/<address>{{wazuhManagerIP}}<\\/address>/g\" /var/ossec/etc/ossec.conf",
          "systemctl daemon-reload",
          "systemctl enable wazuh-agent",
          "systemctl start wazuh-agent",
          "echo 'Wazuh agent installed and configured.'"
        ]
      }
    },
    {
      "action": "aws:runShellScript",
      "name": "ConfigureAuditd",
      "inputs": {
        "runCommand": [
          "#!/bin/bash",
          "echo 'Configuring auditd...'",
          "cat > /etc/audit/rules.d/pci-dss.rules << 'EOL'",
          "# PCI DSS audit rules",
          "-w /etc/passwd -p wa -k identity",
          "-w /etc/group -p wa -k identity",
          "-w /etc/shadow -p wa -k identity",
          "-w /var/log/wtmp -p wa -k session",
          "-w /var/log/btmp -p wa -k session",
          "-w /var/log/lastlog -p wa -k session",
          "-w /var/run/utmp -p wa -k session",
          "-w /etc/sudoers -p wa -k actions",
          "EOL",
          "systemctl enable auditd",
          "systemctl start auditd",
          "echo 'Auditd configured.'"
        ]
      }
    },
    {
      "action": "aws:runShellScript",
      "name": "ConfigureNTP",
      "inputs": {
        "runCommand": [
          "#!/bin/bash",
          "echo 'Configuring NTP services...'",
          "yum install -y chrony",
          "cat > /etc/chrony.conf << EOL",
          "# PCI DSS compliant chrony configuration",
          "server 0.amazon.pool.ntp.org iburst",
          "server 1.amazon.pool.ntp.org iburst",
          "server 2.amazon.pool.ntp.org iburst",
          "server 3.amazon.pool.ntp.org iburst",
          "driftfile /var/lib/chrony/drift",
          "makestep 1.0 3",
          "rtcsync",
          "logdir /var/log/chrony",
          "log tracking measurements statistics",
          "EOL",
          "systemctl enable chronyd",
          "systemctl restart chronyd",
          "echo 'NTP configuration complete.'"
        ]
      }
    }
  ]
}
EOF

# Replace the Wazuh Manager IP placeholder
sed -i "s/WAZUH_MANAGER_IP_PLACEHOLDER/$WAZUH_MANAGER_IP/g" pci-dss-hardening.json

# Check if this is a dry run
if [ "$DRY_RUN" = "TRUE" ]; then
  echo "DRY RUN MODE - Not making any changes"
  echo "Would create SSM document 'PCI-DSS-Hardening' with content:"
  cat pci-dss-hardening.json
  echo "Would run this document on instances: $INSTANCE_IDS"
  echo "Dry run complete."
else
  # Create the SSM document
  aws ssm create-document \
    --content file://pci-dss-hardening.json \
    --name "PCI-DSS-Hardening" \
    --document-type "Command" \
    --region "$AWS_REGION"

  echo "SSM document created. Applying PCI DSS hardening to instances..."

  # Run the SSM command on the instances
  aws ssm send-command \
    --document-name "PCI-DSS-Hardening" \
    --targets "Key=instanceids,Values=$INSTANCE_IDS" \
    --parameters "wazuhManagerIP=$WAZUH_MANAGER_IP" \
    --comment "Applying PCI DSS hardening" \
    --region "$AWS_REGION" \
    --output json

  echo "PCI DSS hardening command sent. Checking command status..."

  # Sleep for a moment to allow command to initialize
  sleep 5

  # Get the command ID from the last run command
  COMMAND_ID=$(aws ssm list-commands --region "$AWS_REGION" --query "Commands[0].CommandId" --output text)

  echo "Command ID: $COMMAND_ID"
  echo "You can check the command status with:"
  echo "aws ssm list-command-invocations --command-id $COMMAND_ID --details --region $AWS_REGION"
fi

# Cleanup
rm pci-dss-hardening.json
