#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, pipe failures

# CLOUDSHELL USAGE:
# Domain SID is pre-configured in the script (see Variables section)
# Just run: chmod +x connector_ad.sh && ./connector_ad.sh
#
# OPTIONAL OVERRIDES:
# Option 1: Override base DOMAIN_SID (script calculates -515 and -513 automatically):
# export DOMAIN_SID="S-1-5-21-1234567890-1234567890-1234567890"
#
# Option 2: Set individual SIDs directly:
# export DOMAIN_COMPUTERS_SID="S-1-5-21-1234567890-1234567890-1234567890-515"
# export DOMAIN_USERS_SID="S-1-5-21-1234567890-1234567890-1234567890-513"
# 
# To get your domain SID:
# Method 1 (Domain-joined Windows): (Get-ADDomain).DomainSID.Value
# Method 2 (AWS API): aws ds describe-directories --directory-ids <directory-id> --query 'DirectoryDescriptions[0].OwnerDirectoryDescription.DomainSid' --output text
#          NOTE: This command works but AWS Managed Microsoft AD doesn't expose domain SID via API for security reasons
#          Use this command from domain-joined workstation for AWS Managed Microsoft AD
# Method 3 (Windows CMD): wmic useraccount where name='Administrator' get sid (remove RID suffix)
# Method 4 (ADUC): Right-click domain → Properties → Attribute Editor → objectSid
#
# NOTE: The command 'aws ds describe-directories' works from anywhere with AWS credentials but:
# ✅ Returns directory info successfully
# ❌ Does NOT return domain SID for AWS Managed Microsoft AD (security restriction)
# ❌ SID is not exposed so doesn't work via CloudShell
# ✅ Works from: Domain-joined workstations only (for domain SID retrieval)
# ⚠️  Requires ds:DescribeDirectories permission
#
# For CloudShell specifically:
# Domain SID is already configured - just run:
# chmod +x connector_ad.sh
# ./connector_ad.sh
#
# To override the hardcoded SID, set environment variable:
# export DOMAIN_SID="S-1-5-21-1234567890-1234567890-1234567890"

# SECURITY: Logging and error handling functions
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2; }
error_exit() { log "ERROR: $1"; exit 1; }

# Variables
VPC_ID="<vpc-id>"
VPC_CIDR="10.192.0.0/16"
DIRECTORY_ID="<directory-id>"
CONNECTOR_NAME="ACM-PCA-AD-Connector"
CA_ARN="arn:aws:acm-pca:<region>:<account-id>:certificate-authority/<ca-id>"
DOMAIN_SID="<domain-sid>"  # Set your domain SID here

# SECURITY: Input validation
log "Starting ACM PCA Connector deployment..."
[[ -n "$VPC_ID" ]] || error_exit "VPC_ID is required"
[[ -n "$DIRECTORY_ID" ]] || error_exit "DIRECTORY_ID is required"
[[ -n "$CA_ARN" ]] || error_exit "CA_ARN is required"

# DOMAIN SID VALIDATION ALERT
if [[ -z "${DOMAIN_SID:-}" ]]; then
  log "⚠️  WARNING: DOMAIN_SID environment variable is NOT set!"
  log "⚠️  Please run: export DOMAIN_SID='<domain-sid>'"
  log "⚠️  See notes.md for instructions on how to get your domain SID"
  log "⚠️  Script will attempt to retrieve SID automatically from AWS Directory Service"
else
  log "✅ DOMAIN_SID is set: $DOMAIN_SID"
  if [[ $DOMAIN_SID =~ ^S-1-5-21-[0-9]+-[0-9]+-[0-9]+$ ]]; then
    log "✅ DOMAIN_SID format is valid"
  else
    error_exit "❌ DOMAIN_SID format is invalid. Expected: S-1-5-21-XXXXXXXX-XXXXXXXX-XXXXXXXX"
  fi
fi

log "Input validation completed successfully"

# SECURITY: Get domain SIDs (priority: individual SIDs > environment override > hardcoded > AWS API)
if [[ -n "${DOMAIN_COMPUTERS_SID:-}" && -n "${DOMAIN_USERS_SID:-}" ]]; then
  log "Using provided individual domain SIDs directly"
elif [[ -n "${DOMAIN_SID:-}" ]]; then
  log "Using domain SID: $DOMAIN_SID"
  DOMAIN_COMPUTERS_SID="${DOMAIN_SID}-515"
  DOMAIN_USERS_SID="${DOMAIN_SID}-513"
else
  log "No domain SID provided - attempting to retrieve automatically from AWS Directory Service..."
  DOMAIN_INFO=$(timeout 30 aws ds describe-directories --directory-ids "$DIRECTORY_ID" --query 'DirectoryDescriptions[0]' --output json 2>/dev/null)
  AWS_EXIT_CODE=$?
  
  if [[ $AWS_EXIT_CODE -eq 0 && -n "$DOMAIN_INFO" ]]; then
    DOMAIN_SID=$(echo "$DOMAIN_INFO" | grep -o 'S-1-5-21-[0-9]*-[0-9]*-[0-9]*' | head -1)
    if [[ -n "$DOMAIN_SID" ]]; then
      log "✅ SUCCESS: Retrieved domain SID automatically via AWS API"
      DOMAIN_COMPUTERS_SID="${DOMAIN_SID}-515"
      DOMAIN_USERS_SID="${DOMAIN_SID}-513"
    else
      log "❌ FAILED: AWS API call succeeded but no domain SID found in response"
    fi
  else
    log "❌ FAILED: AWS API call failed (exit code: $AWS_EXIT_CODE)"
    log "   Likely cause: Missing ds:DescribeDirectories permission or invalid directory ID"
  fi
  
  # Only clear SIDs if we have no SID at all (no hardcoded, no environment, no API success)
  if [[ -z "${DOMAIN_COMPUTERS_SID:-}" || -z "${DOMAIN_USERS_SID:-}" ]]; then
    log "⚠️  WARNING: No domain SID available from any source - PCA Connector will be created without domain SID configuration"
    log "⚠️  You can add domain SIDs later via AWS Console or CLI"
    log "To fix this, set: export DOMAIN_SID='<domain-sid>'"
    DOMAIN_SID=""
    DOMAIN_COMPUTERS_SID=""
    DOMAIN_USERS_SID=""
  fi
fi
log "Domain SID: $DOMAIN_SID"
log "Domain Computers SID: $DOMAIN_COMPUTERS_SID"
log "Domain Users SID: $DOMAIN_USERS_SID"

# SECURITY GROUP CONFIGURATION
# Best Practice: Principle of least privilege - minimal required ports only
# Port 443: HTTPS for secure certificate enrollment and management
# Port 135: RPC Endpoint Mapper (restricted to AD subnets only)
# Port 49152-65535: Dynamic RPC ports (restricted range for AD communication)
# CIDR: Restrict to AD subnets instead of entire VPC for enhanced security

# Create Security Group with error handling
log "Creating security group: ${CONNECTOR_NAME}-SecurityGroup"
SG_ID=$(aws ec2 create-security-group --group-name "${CONNECTOR_NAME}-SecurityGroup" --description "Security group for ACM PCA Connector" --vpc-id "$VPC_ID" --query 'GroupId' --output text) || error_exit "Failed to create security group"
[[ -n "$SG_ID" ]] || error_exit "Security group ID is empty"
log "Security group created: $SG_ID"

# Add security group tags for better management
aws ec2 create-tags --resources $SG_ID --tags Key=Name,Value="${CONNECTOR_NAME}-SecurityGroup" Key=Purpose,Value="PCA-Connector-AD"

# HTTPS for certificate enrollment (allow from VPC)
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 443 --cidr $VPC_CIDR

# RPC Endpoint Mapper (restrict to AD subnets - update CIDR as needed)
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 135 --cidr $VPC_CIDR

# Dynamic RPC ports for AD communication (restrict range for security)
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 49152-65535 --cidr $VPC_CIDR

# LDAP ports for applications that need directory queries (REMOVE IF NOT NEEDED)
# PCA Connector itself doesn't require LDAP - only add if you have applications that query AD objects
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 389 --cidr $VPC_CIDR   # LDAP
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 636 --cidr $VPC_CIDR   # LDAPS

# SECURITY: Remove default outbound rule (0.0.0.0/0) and add specific outbound rules
aws ec2 revoke-security-group-egress --group-id $SG_ID --protocol all --cidr 0.0.0.0/0

# Outbound rules - restrict to only required destinations (best practice)
aws ec2 authorize-security-group-egress --group-id $SG_ID --protocol tcp --port 443 --cidr 0.0.0.0/0    # HTTPS to AWS APIs
aws ec2 authorize-security-group-egress --group-id $SG_ID --protocol tcp --port 135 --cidr $VPC_CIDR    # RPC to AD
aws ec2 authorize-security-group-egress --group-id $SG_ID --protocol tcp --port 49152-65535 --cidr $VPC_CIDR  # Dynamic RPC to AD
aws ec2 authorize-security-group-egress --group-id $SG_ID --protocol tcp --port 389 --cidr $VPC_CIDR    # LDAP to AD (if needed)
aws ec2 authorize-security-group-egress --group-id $SG_ID --protocol tcp --port 636 --cidr $VPC_CIDR    # LDAPS to AD (if needed)
aws ec2 authorize-security-group-egress --group-id $SG_ID --protocol udp --port 53 --cidr $VPC_CIDR     # DNS resolution

# Optional: Add specific AD subnet restrictions (uncomment and modify as needed)
# aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 135 --cidr 10.192.1.0/24
# aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 49152-65535 --cidr 10.192.1.0/24
# aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 389 --cidr 10.192.1.0/24
# aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 636 --cidr 10.192.1.0/24

# IAM ROLE CONFIGURATION
# Best Practice: Service-linked role with fine-grained permissions
# Principal: pca-connector-ad.amazonaws.com (AWS service)
# Policies: Custom policy with least privilege access to specific resources
# Tags: Added for resource management and compliance

# Create IAM Role with tags
aws iam create-role --role-name "${CONNECTOR_NAME}-ServiceRole" \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "pca-connector-ad.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }' \
  --description "Service role for ACM PCA Connector AD" \
  --tags Key=Name,Value="${CONNECTOR_NAME}-ServiceRole" Key=Purpose,Value="PCA-Connector-AD" Key=Environment,Value="Production"

# Add comprehensive IAM policy with fine-grained permissions
aws iam put-role-policy --role-name "${CONNECTOR_NAME}-ServiceRole" --policy-name "PCAConnectorADPolicy" --policy-document "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {
      \"Sid\": \"ACMPCAPermissions\",
      \"Effect\": \"Allow\",
      \"Action\": [
        \"acm-pca:IssueCertificate\",
        \"acm-pca:GetCertificate\",
        \"acm-pca:GetCertificateAuthorityCertificate\",
        \"acm-pca:DescribeCertificateAuthority\",
        \"acm-pca:GetCertificateAuthorityCsr\",
        \"acm-pca:ListCertificateAuthorities\"
      ],
      \"Resource\": \"$CA_ARN\"
    },
    {
      \"Sid\": \"DirectoryServicePermissions\",
      \"Effect\": \"Allow\",
      \"Action\": [
        \"ds:DescribeDirectories\",
        \"ds:AuthorizeApplication\",
        \"ds:UnauthorizeApplication\",
        \"ds:DescribeTrusts\"
      ],
      \"Resource\": \"arn:aws:ds:*:*:directory/$DIRECTORY_ID\"
    },
    {
      \"Sid\": \"EC2NetworkPermissions\",
      \"Effect\": \"Allow\",
      \"Action\": [
        \"ec2:DescribeVpcs\",
        \"ec2:DescribeSubnets\",
        \"ec2:DescribeSecurityGroups\",
        \"ec2:DescribeNetworkInterfaces\",
        \"ec2:CreateNetworkInterface\",
        \"ec2:DeleteNetworkInterface\",
        \"ec2:AttachNetworkInterface\",
        \"ec2:DetachNetworkInterface\"
      ],
      \"Resource\": \"*\",
      \"Condition\": {
        \"StringEquals\": {
          \"ec2:vpc\": \"arn:aws:ec2:*:*:vpc/$VPC_ID\"
        }
      }
    },
    {
      \"Sid\": \"LoggingPermissions\",
      \"Effect\": \"Allow\",
      \"Action\": [
        \"logs:CreateLogGroup\",
        \"logs:CreateLogStream\",
        \"logs:PutLogEvents\",
        \"logs:DescribeLogGroups\",
        \"logs:DescribeLogStreams\"
      ],
      \"Resource\": \"arn:aws:logs:*:*:log-group:/aws/pca-connector-ad/*\"
    }
  ]
}"

log "Retrieving IAM role ARN..."
ROLE_ARN=$(aws iam get-role --role-name "${CONNECTOR_NAME}-ServiceRole" --query 'Role.Arn' --output text) || error_exit "Failed to get IAM role ARN"
[[ -n "$ROLE_ARN" ]] || error_exit "Role ARN is empty"
log "IAM role retrieved: $ROLE_ARN"

# Create PCA Connector with error handling
log "Creating PCA Connector..."
CONNECTOR_ARN=$(aws pca-connector-ad create-connector \
  --certificate-authority-arn "$CA_ARN" \
  --directory-id "$DIRECTORY_ID" \
  --vpc-information SecurityGroupIds="$SG_ID" \
  --query 'ConnectorArn' --output text) || error_exit "Failed to create PCA connector"
[[ -n "$CONNECTOR_ARN" ]] || error_exit "Connector ARN is empty"
log "PCA Connector created successfully: $CONNECTOR_ARN"

# Wait for connector to become ACTIVE before creating SPN
# Typical wait time: 2-5 minutes (up to 10 minutes maximum)
# Checks status every 30 seconds until ACTIVE
log "Waiting for connector to become active (typically 2-5 minutes)..."
while true; do
  CONNECTOR_STATUS=$(aws pca-connector-ad get-connector --connector-arn "$CONNECTOR_ARN" --query 'Connector.Status' --output text)
  if [[ "$CONNECTOR_STATUS" == "ACTIVE" ]]; then
    log "Connector is now active"
    break
  elif [[ "$CONNECTOR_STATUS" == "FAILED" ]]; then
    error_exit "Connector creation failed"
  else
    log "Connector status: $CONNECTOR_STATUS - waiting 30 seconds..."
    sleep 30
  fi
done

# Create Service Principal Name for the connector
log "Creating Service Principal Name..."
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
AWS_REGION=$(aws configure get region || echo "us-east-1")
SPN_ARN=$(aws pca-connector-ad create-service-principal-name \
  --connector-arn "$CONNECTOR_ARN" \
  --directory-registration-arn "arn:aws:pca-connector-ad:${AWS_REGION}:${AWS_ACCOUNT_ID}:directory-registration/$DIRECTORY_ID" \
  --query 'ServicePrincipalNameArn' --output text) || error_exit "Failed to create SPN"
[[ -n "$SPN_ARN" ]] || error_exit "SPN ARN is empty"
log "Service Principal Name created successfully: $SPN_ARN"

# Create template files with PKI best practices

# COMPUTER CERTIFICATE TEMPLATE
# Purpose: Machine authentication for domain computers
# Best Practice: AutoEnroll enabled for seamless machine certificate deployment
# Validity: 1 year (standard for machine certificates)
# Key Usage: DigitalSignature + KeyEncipherment for authentication and encryption
# Policy: CLIENT_AUTHENTICATION for machine-to-machine authentication
cat > computer-template.json << 'EOF'
{
  "TemplateV4": {
    "CertificateValidity": {"ValidityPeriod": {"Period": 365, "PeriodType": "DAYS"}, "RenewalPeriod": {"Period": 30, "PeriodType": "DAYS"}},
    "EnrollmentFlags": {"EnableKeyReuseOnNtTokenKeysetStorageFull": false, "IncludeSymmetricAlgorithms": false, "UserInteractionRequired": false},
    "Extensions": {"KeyUsage": {"UsageFlags": {"DigitalSignature": true, "KeyEncipherment": true}, "Critical": true}, "ApplicationPolicies": {"Policies": [{"PolicyType": "CLIENT_AUTHENTICATION"}], "Critical": false}},
    "GeneralFlags": {"AutoEnrollment": true, "MachineType": true},
    "HashAlgorithm": "SHA512",
    "PrivateKeyAttributes": {"KeySpec": "KEY_EXCHANGE", "MinimalKeyLength": 2048, "CryptoProviders": ["Microsoft RSA SChannel Cryptographic Provider"], "KeyUsageProperty": {"PropertyFlags": {"Decrypt": true, "KeyAgreement": true}}, "Algorithm": "RSA"},
    "PrivateKeyFlags": {"ClientVersion": "WINDOWS_SERVER_2016"},
    "SubjectNameFlags": {"RequireCommonName": true, "RequireDnsAsCn": false, "SanRequireDns": true}
  }
}
EOF

# LAPTOP CERTIFICATE TEMPLATE  
# Purpose: Mobile device authentication (laptops, tablets)
# Best Practice: Same as computer template but may have different renewal policies
# AutoEnroll: Enabled for automatic certificate provisioning
# SanRequireDns: Required for proper hostname validation
cat > laptop-template.json << 'EOF'
{
  "TemplateV4": {
    "CertificateValidity": {"ValidityPeriod": {"Period": 365, "PeriodType": "DAYS"}, "RenewalPeriod": {"Period": 30, "PeriodType": "DAYS"}},
    "EnrollmentFlags": {"EnableKeyReuseOnNtTokenKeysetStorageFull": false, "IncludeSymmetricAlgorithms": false, "UserInteractionRequired": false},
    "Extensions": {"KeyUsage": {"UsageFlags": {"DigitalSignature": true, "KeyEncipherment": true}, "Critical": true}, "ApplicationPolicies": {"Policies": [{"PolicyType": "CLIENT_AUTHENTICATION"}], "Critical": false}},
    "GeneralFlags": {"AutoEnrollment": true, "MachineType": true},
    "HashAlgorithm": "SHA512",
    "PrivateKeyAttributes": {"KeySpec": "KEY_EXCHANGE", "MinimalKeyLength": 2048, "CryptoProviders": ["Microsoft RSA SChannel Cryptographic Provider"], "KeyUsageProperty": {"PropertyFlags": {"Decrypt": true, "KeyAgreement": true}}, "Algorithm": "RSA"},
    "PrivateKeyFlags": {"ClientVersion": "WINDOWS_SERVER_2016"},
    "SubjectNameFlags": {"RequireCommonName": true, "RequireDnsAsCn": false, "SanRequireDns": true}
  }
}
EOF

# SERVER CERTIFICATE TEMPLATE
# Purpose: Server authentication for infrastructure services
# Best Practice: 2-year validity for infrastructure stability
# AutoEnroll: Disabled - servers require manual certificate management
# Policy: SERVER_AUTHENTICATION for TLS/SSL server certificates
# SanRequireDns: Required for proper FQDN validation
cat > server-template.json << 'EOF'
{
  "TemplateV4": {
    "CertificateValidity": {"ValidityPeriod": {"Period": 730, "PeriodType": "DAYS"}, "RenewalPeriod": {"Period": 60, "PeriodType": "DAYS"}},
    "EnrollmentFlags": {"EnableKeyReuseOnNtTokenKeysetStorageFull": false, "IncludeSymmetricAlgorithms": false, "UserInteractionRequired": false},
    "Extensions": {"KeyUsage": {"UsageFlags": {"DigitalSignature": true, "KeyEncipherment": true}, "Critical": true}, "ApplicationPolicies": {"Policies": [{"PolicyType": "SERVER_AUTHENTICATION"}], "Critical": false}},
    "GeneralFlags": {"AutoEnrollment": false, "MachineType": true},
    "HashAlgorithm": "SHA512",
    "PrivateKeyAttributes": {"KeySpec": "KEY_EXCHANGE", "MinimalKeyLength": 2048, "CryptoProviders": ["Microsoft RSA SChannel Cryptographic Provider"], "KeyUsageProperty": {"PropertyFlags": {"Decrypt": true, "KeyAgreement": true}}, "Algorithm": "RSA"},
    "PrivateKeyFlags": {"ClientVersion": "WINDOWS_SERVER_2016"},
    "SubjectNameFlags": {"RequireCommonName": true, "RequireDnsAsCn": false, "SanRequireDns": true}
  }
}
EOF

# USER CERTIFICATE TEMPLATE
# Purpose: User authentication and encryption
# Best Practice: MachineType=false for user certificates
# AutoEnroll: Disabled - users should request certificates manually
# Policy: CLIENT_AUTHENTICATION for user authentication scenarios
# Validity: 1 year standard for user certificates
cat > user-template.json << 'EOF'
{
  "TemplateV4": {
    "CertificateValidity": {"ValidityPeriod": {"Period": 365, "PeriodType": "DAYS"}, "RenewalPeriod": {"Period": 30, "PeriodType": "DAYS"}},
    "EnrollmentFlags": {"EnableKeyReuseOnNtTokenKeysetStorageFull": false, "IncludeSymmetricAlgorithms": false, "UserInteractionRequired": false},
    "Extensions": {"KeyUsage": {"UsageFlags": {"DigitalSignature": true, "KeyEncipherment": true}, "Critical": true}, "ApplicationPolicies": {"Policies": [{"PolicyType": "CLIENT_AUTHENTICATION"}], "Critical": false}},
    "GeneralFlags": {"AutoEnrollment": false, "MachineType": false},
    "HashAlgorithm": "SHA512",
    "PrivateKeyAttributes": {"KeySpec": "KEY_EXCHANGE", "MinimalKeyLength": 2048, "CryptoProviders": ["Microsoft RSA SChannel Cryptographic Provider"], "KeyUsageProperty": {"PropertyFlags": {"Decrypt": true, "KeyAgreement": true}}, "Algorithm": "RSA"},
    "PrivateKeyFlags": {"ClientVersion": "WINDOWS_SERVER_2016"},
    "SubjectNameFlags": {"RequireCommonName": true, "RequireDnsAsCn": false, "SanRequireDns": false}
  }
}
EOF

# WEB SERVER CERTIFICATE TEMPLATE
# Purpose: Web server SSL/TLS certificates
# Best Practice: 2-year validity for web infrastructure
# AutoEnroll: Disabled - web servers require controlled certificate deployment
# Policy: SERVER_AUTHENTICATION for HTTPS/TLS
# SanRequireDns: Critical for web certificate validation
cat > web-template.json << 'EOF'
{
  "TemplateV4": {
    "CertificateValidity": {"ValidityPeriod": {"Period": 730, "PeriodType": "DAYS"}, "RenewalPeriod": {"Period": 60, "PeriodType": "DAYS"}},
    "EnrollmentFlags": {"EnableKeyReuseOnNtTokenKeysetStorageFull": false, "IncludeSymmetricAlgorithms": false, "UserInteractionRequired": false},
    "Extensions": {"KeyUsage": {"UsageFlags": {"DigitalSignature": true, "KeyEncipherment": true}, "Critical": true}, "ApplicationPolicies": {"Policies": [{"PolicyType": "SERVER_AUTHENTICATION"}], "Critical": false}},
    "GeneralFlags": {"AutoEnrollment": false, "MachineType": true},
    "HashAlgorithm": "SHA512",
    "PrivateKeyAttributes": {"KeySpec": "KEY_EXCHANGE", "MinimalKeyLength": 2048, "CryptoProviders": ["Microsoft RSA SChannel Cryptographic Provider"], "KeyUsageProperty": {"PropertyFlags": {"Decrypt": true, "KeyAgreement": true}}, "Algorithm": "RSA"},
    "PrivateKeyFlags": {"ClientVersion": "WINDOWS_SERVER_2016"},
    "SubjectNameFlags": {"RequireCommonName": true, "RequireDnsAsCn": false, "SanRequireDns": true}
  }
}
EOF

# CODE SIGNING CERTIFICATE TEMPLATE
# Purpose: Digital signing of applications and scripts
# Best Practice: Manual enrollment only for security
# Key Usage: DigitalSignature only (no encryption needed)
# Policy: CODE_SIGNING for Authenticode and script signing
# KeyAgreement: Required for KEY_EXCHANGE compatibility
cat > codesign-template.json << 'EOF'
{
  "TemplateV4": {
    "CertificateValidity": {"ValidityPeriod": {"Period": 365, "PeriodType": "DAYS"}, "RenewalPeriod": {"Period": 30, "PeriodType": "DAYS"}},
    "EnrollmentFlags": {"EnableKeyReuseOnNtTokenKeysetStorageFull": false, "IncludeSymmetricAlgorithms": false, "UserInteractionRequired": false},
    "Extensions": {"KeyUsage": {"UsageFlags": {"DigitalSignature": true}, "Critical": true}, "ApplicationPolicies": {"Policies": [{"PolicyType": "CODE_SIGNING"}], "Critical": false}},
    "GeneralFlags": {"AutoEnrollment": true, "MachineType": false},
    "HashAlgorithm": "SHA512",
    "PrivateKeyAttributes": {"KeySpec": "KEY_EXCHANGE", "MinimalKeyLength": 2048, "CryptoProviders": ["Microsoft Software Key Storage Provider"], "KeyUsageProperty": {"PropertyFlags": {"Sign": true, "KeyAgreement": true}}, "Algorithm": "RSA"},
    "PrivateKeyFlags": {"ClientVersion": "WINDOWS_SERVER_2016"},
    "SubjectNameFlags": {"RequireCommonName": true, "RequireDnsAsCn": false}
  }
}
EOF

# EMAIL CERTIFICATE TEMPLATE (S/MIME)
# Purpose: Email encryption and digital signatures
# Best Practice: User-based certificate for email protection
# Policy: CLIENT_AUTHENTICATION for S/MIME support
# SanRequireEmail: Required for email address validation
# Key Usage: Both signing and encryption for full S/MIME support
cat > email-template.json << 'EOF'
{
  "TemplateV4": {
    "CertificateValidity": {"ValidityPeriod": {"Period": 365, "PeriodType": "DAYS"}, "RenewalPeriod": {"Period": 30, "PeriodType": "DAYS"}},
    "EnrollmentFlags": {"EnableKeyReuseOnNtTokenKeysetStorageFull": false, "IncludeSymmetricAlgorithms": false, "UserInteractionRequired": false},
    "Extensions": {"KeyUsage": {"UsageFlags": {"DigitalSignature": true, "KeyEncipherment": true, "NonRepudiation": true}, "Critical": true}, "ApplicationPolicies": {"Policies": [{"PolicyType": "CLIENT_AUTHENTICATION"}], "Critical": false}},
    "GeneralFlags": {"AutoEnrollment": false, "MachineType": false},
    "HashAlgorithm": "SHA256",
    "PrivateKeyAttributes": {"KeySpec": "KEY_EXCHANGE", "MinimalKeyLength": 2048, "KeyUsageProperty": {"PropertyFlags": {"Sign": true, "Decrypt": true, "KeyAgreement": true}}, "Algorithm": "RSA"},
    "PrivateKeyFlags": {"ClientVersion": "WINDOWS_SERVER_2016"},
    "SubjectNameFlags": {"RequireCommonName": true, "RequireDnsAsCn": false, "SanRequireEmail": true}
  }
}
EOF


# ENROLLMENT AGENT CERTIFICATE TEMPLATE
# Purpose: Certificate enrollment delegation for Parallels RAS
# Best Practice: Allows designated users to enroll certificates on behalf of others
# Policy: ENROLLMENT_AGENT for certificate enrollment delegation
# AutoEnroll: Disabled - requires manual assignment to trusted users
# Validity: 2 years for administrative stability
cat > enrollmentagent-template.json << 'EOF'
{
  "TemplateV4": {
    "CertificateValidity": {"ValidityPeriod": {"Period": 730, "PeriodType": "DAYS"}, "RenewalPeriod": {"Period": 60, "PeriodType": "DAYS"}},
    "EnrollmentFlags": {"EnableKeyReuseOnNtTokenKeysetStorageFull": false, "IncludeSymmetricAlgorithms": false, "UserInteractionRequired": false},
    "Extensions": {"KeyUsage": {"UsageFlags": {"DigitalSignature": true, "KeyEncipherment": true}, "Critical": true}, "ApplicationPolicies": {"Policies": [{"PolicyType": "CERTIFICATE_REQUEST_AGENT"}], "Critical": false}},
    "GeneralFlags": {"AutoEnrollment": false, "MachineType": false},
    "PrivateKeyAttributes": {"KeySpec": "KEY_EXCHANGE", "MinimalKeyLength": 2048, "CryptoProviders": ["Microsoft RSA SChannel Cryptographic Provider"], "KeyUsageProperty": {"PropertyFlags": {"Decrypt": true, "KeyAgreement": true}}, "Algorithm": "RSA"},
    "PrivateKeyFlags": {"ClientVersion": "WINDOWS_SERVER_2016"},
    "SubjectNameFlags": {"RequireCommonName": true, "RequireDnsAsCn": false, "SanRequireUpn": true}
  }
}
EOF

# SMART CARD CERTIFICATE TEMPLATE
# Purpose: Smart card logon and strong authentication
# Best Practice: Short validity (180 days) for enhanced security
# UserInteractionRequired: true for smart card PIN verification
# Policy: SMART_CARD_LOGON + CLIENT_AUTHENTICATION
# CryptoProvider: Smart Card specific provider
# SanRequireUpn: Required for user principal name validation

cat > smartcard-template.json << 'EOF'
{
  "TemplateV4": {
    "CertificateValidity": {"ValidityPeriod": {"Period": 180, "PeriodType": "DAYS"}, "RenewalPeriod": {"Period": 14, "PeriodType": "DAYS"}},
    "EnrollmentFlags": {"EnableKeyReuseOnNtTokenKeysetStorageFull": false, "IncludeSymmetricAlgorithms": false, "UserInteractionRequired": false},
    "Extensions": {"KeyUsage": {"UsageFlags": {"DigitalSignature": true, "KeyEncipherment": true}, "Critical": true}, "ApplicationPolicies": {"Policies": [{"PolicyType": "CLIENT_AUTHENTICATION"}, {"PolicyType": "SMART_CARD_LOGIN"}], "Critical": false}},
    "GeneralFlags": {"AutoEnrollment": false, "MachineType": false},
    "HashAlgorithm": "SHA512",
    "PrivateKeyAttributes": {"KeySpec": "KEY_EXCHANGE", "MinimalKeyLength": 2048, "KeyUsageProperty": {"PropertyFlags": {"Decrypt": true, "KeyAgreement": true}}, "Algorithm": "RSA"},
    "PrivateKeyFlags": {"ClientVersion": "WINDOWS_SERVER_2016"},
    "SubjectNameFlags": {"RequireDirectoryPath": true, "RequireDnsAsCn": false, "SanRequireUpn": true}
  }
}
EOF

# CERTIFICATE TEMPLATE CREATION
# Deploy all certificate templates to the PCA Connector
# Each template serves specific PKI use cases for enterprise environments

# Create Certificate Templates with error handling
log "Creating certificate templates..."
log "Connector ARN: $CONNECTOR_ARN"
log "Checking if computer-template.json exists..."
ls -la computer-template.json || error_exit "computer-template.json not found"
log "Creating certificate template..."
COMP_TEMPLATE_ARN=$(aws pca-connector-ad create-template --connector-arn "$CONNECTOR_ARN" --name "WorkstationCertificateTemplate" --definition file://computer-template.json --query 'TemplateArn' --output text) || error_exit "Failed to create Computer template"
[[ -n "$COMP_TEMPLATE_ARN" ]] || error_exit "Computer template ARN is empty"
COMPUTER_TEMPLATE_ARN="$COMP_TEMPLATE_ARN"
log "Computer certificate template created: $COMPUTER_TEMPLATE_ARN"
LAPTOP_TEMPLATE_ARN=$(aws pca-connector-ad create-template --connector-arn $CONNECTOR_ARN --name "LaptopCertificateTemplate" --definition file://laptop-template.json --query 'TemplateArn' --output text)
SERVER_TEMPLATE_ARN=$(aws pca-connector-ad create-template --connector-arn $CONNECTOR_ARN --name "InfrastructureServerTemplate" --definition file://server-template.json --query 'TemplateArn' --output text)
USER_TEMPLATE_ARN=$(aws pca-connector-ad create-template --connector-arn $CONNECTOR_ARN --name "UserAuthenticationTemplate" --definition file://user-template.json --query 'TemplateArn' --output text)
WEB_TEMPLATE_ARN=$(aws pca-connector-ad create-template --connector-arn $CONNECTOR_ARN --name "WebServerTemplate" --definition file://web-template.json --query 'TemplateArn' --output text)
CODESIGN_TEMPLATE_ARN=$(aws pca-connector-ad create-template --connector-arn $CONNECTOR_ARN --name "CodeSigningTemplate" --definition file://codesign-template.json --query 'TemplateArn' --output text)
EMAIL_TEMPLATE_ARN=$(aws pca-connector-ad create-template --connector-arn $CONNECTOR_ARN --name "EmailTemplate" --definition file://email-template.json --query 'TemplateArn' --output text)
ENROLLMENTAGENT_TEMPLATE_ARN=$(aws pca-connector-ad create-template --connector-arn $CONNECTOR_ARN --name "EnrollmentAgentTemplate" --definition file://enrollmentagent-template.json --query 'TemplateArn' --output text)
SMARTCARD_TEMPLATE_ARN=$(aws pca-connector-ad create-template --connector-arn $CONNECTOR_ARN --name "SmartCardTemplate" --definition file://smartcard-template.json --query 'TemplateArn' --output text)

# TEMPLATE ACCESS CONTROL ENTRIES
# Best Practice: Principle of least privilege - grant minimal required permissions
# Domain Computers (SID ending -515): Machine certificates with AutoEnroll
# Domain Users (SID ending -513): User certificates with manual enrollment only
# AutoEnroll=ALLOW: Automatic certificate enrollment (machines only)
# AutoEnroll=DENY: Manual enrollment required (users and servers)

# VALIDATE SIDs BEFORE ACCESS CONTROL CONFIGURATION
log "Validating SIDs for access control entries..."
if [[ -z "${DOMAIN_COMPUTERS_SID:-}" || -z "${DOMAIN_USERS_SID:-}" ]]; then
  error_exit "❌ Domain SIDs are not set. Cannot configure access control entries."
fi
log "✅ Using Domain Computers SID: $DOMAIN_COMPUTERS_SID"
log "✅ Using Domain Users SID: $DOMAIN_USERS_SID"

# Create Template Group Access Control Entries
log "Creating template access control entries..."
aws pca-connector-ad create-template-group-access-control-entry --template-arn "$COMPUTER_TEMPLATE_ARN" --group-security-identifier "$DOMAIN_COMPUTERS_SID" --access-rights AutoEnroll=ALLOW,Enroll=ALLOW --group-display-name "Domain Computers"
aws pca-connector-ad create-template-group-access-control-entry --template-arn "$LAPTOP_TEMPLATE_ARN" --group-security-identifier "$DOMAIN_COMPUTERS_SID" --access-rights AutoEnroll=ALLOW,Enroll=ALLOW --group-display-name "Domain Computers"
aws pca-connector-ad create-template-group-access-control-entry --template-arn "$SERVER_TEMPLATE_ARN" --group-security-identifier "$DOMAIN_COMPUTERS_SID" --access-rights AutoEnroll=DENY,Enroll=ALLOW --group-display-name "Domain Computers"
aws pca-connector-ad create-template-group-access-control-entry --template-arn "$USER_TEMPLATE_ARN" --group-security-identifier "$DOMAIN_USERS_SID" --access-rights AutoEnroll=DENY,Enroll=ALLOW --group-display-name "Domain Users"
aws pca-connector-ad create-template-group-access-control-entry --template-arn "$WEB_TEMPLATE_ARN" --group-security-identifier "$DOMAIN_COMPUTERS_SID" --access-rights AutoEnroll=DENY,Enroll=ALLOW --group-display-name "Domain Computers"
aws pca-connector-ad create-template-group-access-control-entry --template-arn "$CODESIGN_TEMPLATE_ARN" --group-security-identifier "$DOMAIN_USERS_SID" --access-rights AutoEnroll=DENY,Enroll=ALLOW --group-display-name "Domain Users"
aws pca-connector-ad create-template-group-access-control-entry --template-arn "$EMAIL_TEMPLATE_ARN" --group-security-identifier "$DOMAIN_USERS_SID" --access-rights AutoEnroll=DENY,Enroll=ALLOW --group-display-name "Domain Users"
aws pca-connector-ad create-template-group-access-control-entry --template-arn "$ENROLLMENTAGENT_TEMPLATE_ARN" --group-security-identifier "$DOMAIN_USERS_SID" --access-rights AutoEnroll=DENY,Enroll=ALLOW --group-display-name "Domain Users"
aws pca-connector-ad create-template-group-access-control-entry --template-arn "$SMARTCARD_TEMPLATE_ARN" --group-security-identifier "$DOMAIN_USERS_SID" --access-rights AutoEnroll=DENY,Enroll=ALLOW --group-display-name "Domain Users"

# Cleanup
rm -f computer-template.json laptop-template.json server-template.json user-template.json web-template.json codesign-template.json email-template.json enrollmentagent-template.json smartcard-template.json

log "Certificate template deployment completed successfully"
log "Summary:"
log "  - Connector ARN: $CONNECTOR_ARN"
log "  - Security Group: $SG_ID"
log "  - IAM Role: $ROLE_ARN"
log "ACM PCA Connector deployment completed successfully"
