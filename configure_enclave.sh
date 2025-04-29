# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#!/bin/bash
# configure_enclave.sh

# 加载.env文件函数
load_env_file() {
  ENV_FILE=".env"
  if [ -f "$ENV_FILE" ]; then
    echo "正在加载 .env 文件..."
    set -a  # 自动标记读取的变量为export
    source "$ENV_FILE"
    set +a
    echo ".env 文件加载完成"
  else
    echo "没有找到 .env 文件，继续使用默认设置或环境变量"
  fi
}

# Additional information on this script. 
show_help() {
    echo "configure_enclave.sh - Launch AWS EC2 instance with Nitro Enclaves and configure allowed endpoints. "
    echo ""
    echo "This script launches an AWS EC2 instance (m5.xlarge) with Nitro Enclaves enabled."
    echo "By default, it uses the AMI ami-085ad6ae776d8f09c, which works in us-east-1."
    echo "If you change the REGION, you must also supply a valid AMI for that region."
    echo ""
    echo "Pre-requisites:"
    echo "  - allowed_endpoints.yaml is configured with all necessary endpoints that the enclave needs"
    echo "    access to. This is necessary since the enclave doesn't not come with Internet connection,"
    echo "    all traffics needs to be preconfigured for traffic forwarding."
    echo "  - AWS CLI is installed and configured with proper credentials"
    echo "  - The environment variable KEY_PAIR is set (e.g., export KEY_PAIR=my-key)"
    echo "  - The instance type 'm5.xlarge' must be supported in your account/region for Nitro Enclaves"
    echo ""
    echo "Usage:"
    echo "  export KEY_PAIR=<your-key-pair-name>"
    echo "  # optional: export REGION=<your-region>  (defaults to us-east-1)"
    echo "  # optional: export AMI_ID=<your-ami-id>  (defaults to ami-085ad6ae776d8f09c)"
    echo "  # optional: export API_ENV_VAR_NAME=<env-var-name> (defaults to 'API_KEY')"
    echo "  # optional: export INSTANCE_TYPE=<your-instance-type> (defaults to 'm5.xlarge')"
    echo "  # optional: export VPC_ID=<your-vpc-id>  (if not set, uses default VPC or creates a new one)"
    echo "  # optional: create a .env file with the above variables"
    echo "  ./configure_enclave.sh"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show this help message"
    echo ""
    echo ".env 文件说明:"
    echo "  您可以创建一个 .env 文件来设置环境变量，而不是每次都手动导出。"
    echo "  如果存在 .env 文件，脚本会自动加载其中的变量。"
    echo "  运行脚本后，将自动创建一个 .env.example 文件作为参考。"
    echo "  您可以将其复制为 .env 并根据需要修改变量值。"
    echo "  支持的变量包括: KEY_PAIR, REGION, AMI_ID, API_ENV_VAR_NAME, EC2_INSTANCE_NAME,"
    echo "  INSTANCE_TYPE, VPC_ID, USE_SECRET, SECRET_CHOICE, USER_SECRET_NAME, SECRET_VALUE 等。"
    echo ""
    echo "VPC 设置说明:"
    echo "  脚本会自动处理VPC和子网设置:"
    echo "  - 如果指定了VPC_ID，将使用指定的VPC"
    echo "  - 如果未指定VPC_ID，将使用默认VPC"
    echo "  - 如果没有默认VPC，将创建一个新的VPC和子网"
    echo "  - 所有新创建的子网都将是公共子网，允许访问互联网"
}

# Check for help flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# 加载.env文件
load_env_file

############################
# Configurable Defaults
############################
# Sets the region by default to us-east-1
REGION="${REGION:-us-east-1}"
export AWS_DEFAULT_REGION="$REGION"

# The default AMI for us-east-1. Change this if your region is different.
AMI_ID="${AMI_ID:-ami-085ad6ae776d8f09c}"

# 默认实例类型设置为m5.xlarge，但可以通过环境变量覆盖
INSTANCE_TYPE="${INSTANCE_TYPE:-m5.xlarge}"

# Environment variable name for our secret; default is 'API_KEY'
API_ENV_VAR_NAME="${API_ENV_VAR_NAME:-API_KEY}"

############################
# Cleanup Old Files
############################
rm user-data.sh 2>/dev/null
rm trust-policy.json 2>/dev/null
rm secrets-policy.json 2>/dev/null

############################
# Check KEY_PAIR
############################
if [ -z "$KEY_PAIR" ]; then
    echo "Error: Environment variable KEY_PAIR is not set. Please export KEY_PAIR=<your-key-name>."
    exit 1
fi

# Check if yq is available
if ! command -v yq >/dev/null 2>&1; then
  echo "Error: yq is not installed."
  echo "Please install yq (for example: 'brew install yq' on macOS or 'sudo apt-get install yq' on Ubuntu) and try again."
  exit 1
fi

#echo "yq is installed. Proceeding..."

############################
# Set the EC2 Instance Name
############################
if [ -z "$EC2_INSTANCE_NAME" ]; then
    read -p "Enter EC2 instance base name: " EC2_INSTANCE_NAME
else
    echo "使用预设的 EC2_INSTANCE_NAME 值: $EC2_INSTANCE_NAME"
fi

if command -v shuf >/dev/null 2>&1; then
    RANDOM_SUFFIX=$(shuf -i 100000-999999 -n 1)
else
    RANDOM_SUFFIX=$(printf "%06d" $(( RANDOM % 900000 + 100000 )))
fi

FINAL_INSTANCE_NAME="${EC2_INSTANCE_NAME}-${RANDOM_SUFFIX}"
echo "Instance will be named: $FINAL_INSTANCE_NAME"


#########################################
# Read endpoints from allowed_endpoints.yaml
#########################################
if [ -f "src/nautilus-server/allowed_endpoints.yaml" ]; then
    # Use a small Python snippet to parse the YAML and emit space-separated endpoints
    ENDPOINTS=$(yq e '.endpoints | join(" ")' src/nautilus-server/allowed_endpoints.yaml 2>/dev/null)
    if [ -n "$ENDPOINTS" ]; then
        echo "Endpoints found in src/nautilus-server/allowed_endpoints.yaml (before region patching):"
        echo "$ENDPOINTS"

        # Replace any existing region (like us-east-1, us-west-2, etc.) in kms.* / secretsmanager.* with the user-provided $REGION.
        # This way, if $REGION=us-west-2, you'll get kms.us-west-2.amazonaws.com etc.
        ENDPOINTS=$(echo "$ENDPOINTS" \
          | sed "s|kms\.[^.]*\.amazonaws\.com|kms.$REGION.amazonaws.com|g" \
          | sed "s|secretsmanager\.[^.]*\.amazonaws\.com|secretsmanager.$REGION.amazonaws.com|g")
        echo "Endpoints after region patching:"
        echo "$ENDPOINTS"
    else
        echo "No endpoints found in src/nautilus-server/allowed_endpoints.yaml. Continuing without additional endpoints."
    fi
else
    echo "src/nautilus-server/allowed_endpoints.yaml not found. Continuing without additional endpoints."
    ENDPOINTS=""
fi

#########################################
# Decide about secrets (3 scenarios)
#########################################
if [ -z "$USE_SECRET" ]; then
    read -p "Do you want to use a secret? (y/n): " USE_SECRET
else
    echo "使用预设的 USE_SECRET 值: $USE_SECRET"
fi

# Validate input
if [[ ! "$USE_SECRET" =~ ^[YyNn]$ ]]; then
    echo "Error: Please enter 'y' or 'n'"
    exit 1
fi

if [[ "$USE_SECRET" =~ ^[Yy]$ ]]; then
    if [ -z "$SECRET_CHOICE" ]; then
        read -p "Do you want to create a new secret or use an existing secret ARN? (new/existing): " SECRET_CHOICE
    else
        echo "使用预设的 SECRET_CHOICE 值: $SECRET_CHOICE"
    fi

    # Validate input
    if [[ ! "$SECRET_CHOICE" =~ ^([Nn]ew|NEW|[Ee]xisting|EXISTING)$ ]]; then
        echo "Error: Please enter 'new' or 'existing'"
        exit 1
    fi

    if [[ "$SECRET_CHOICE" =~ ^([Nn]ew|NEW)$ ]]; then
        #----------------------------------------------------
        # Create a new secret
        #----------------------------------------------------
        if [ -z "$USER_SECRET_NAME" ]; then
            read -p "Enter secret name: " USER_SECRET_NAME
        else
            echo "使用预设的 USER_SECRET_NAME 值: $USER_SECRET_NAME"
        fi
        
        if [ -z "$SECRET_VALUE" ]; then
            read -s -p "Enter secret value: " SECRET_VALUE
            echo ""
        else
            echo "使用预设的 SECRET_VALUE (值已隐藏)"
        fi
        
        SECRET_NAME="${USER_SECRET_NAME}"
        echo "Creating secret '$SECRET_NAME' in AWS Secrets Manager..."
        SECRET_ARN=$(aws secretsmanager create-secret \
          --name "$SECRET_NAME" \
          --secret-string "$SECRET_VALUE" \
          --region "$REGION" \
          --query 'ARN' --output text)
        echo "Secret created with ARN: $SECRET_ARN"

      # 如果创建失败（比如已存在），自动查找 ARN
      if [ -z "$SECRET_ARN" ]; then
        echo "Secret 创建失败，尝试查找已存在的 Secret ARN..."
        SECRET_ARN=$(aws secretsmanager list-secrets --region "$REGION" \
          --query "SecretList[?Name=='$USER_SECRET_NAME'].ARN | [0]" --output text)
        if [ -z "$SECRET_ARN" ]; then
          echo "未能自动找到 Secret ARN，请手动输入："
          read -p "Secret ARN: " SECRET_ARN
        else
          echo "已自动获取 Secret ARN: $SECRET_ARN"
        fi
      else
        echo "Secret 创建成功，ARN: $SECRET_ARN"
      fi

        # Create IAM Role, Policy, and Instance Profile for Secret Access
        ROLE_NAME="role-${FINAL_INSTANCE_NAME}"
        echo "Creating IAM role '$ROLE_NAME' for the EC2 instance..."

        cat <<EOF > trust-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

        aws iam create-role \
           --role-name "$ROLE_NAME" \
           --assume-role-policy-document file://trust-policy.json > /dev/null 2>&1

        cat <<EOF > secrets-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "$SECRET_ARN"
    }
  ]
}
EOF

        aws iam put-role-policy \
           --role-name "$ROLE_NAME" \
           --policy-name "$FINAL_INSTANCE_NAME" \
           --policy-document file://secrets-policy.json > /dev/null 2>&1

        aws iam create-instance-profile \
           --instance-profile-name "$ROLE_NAME" > /dev/null 2>&1

        aws iam add-role-to-instance-profile \
           --instance-profile-name "$ROLE_NAME" \
           --role-name "$ROLE_NAME" > /dev/null 2>&1

        IAM_INSTANCE_PROFILE_OPTION=""

        # Remove old references first and add new secret fetching logic
        if [[ "$(uname)" == "Darwin" ]]; then
            sed -i '' '/SECRET_VALUE=/d' expose_enclave.sh 2>/dev/null || true
            sed -i '' '/echo.*secrets\.json/d' expose_enclave.sh 2>/dev/null || true
            
            sed -i '' "/# Secrets-block/a\\
SECRET_VALUE=\$(aws secretsmanager get-secret-value --secret-id ${SECRET_ARN} --region ${REGION} | jq -r .SecretString)\\
echo \"\$SECRET_VALUE\" | jq -R '{\"${API_ENV_VAR_NAME}\": .}' > secrets.json\\
" expose_enclave.sh
        else
            sed -i '/SECRET_VALUE=/d' expose_enclave.sh 2>/dev/null || true
            sed -i '/echo.*secrets\.json/d' expose_enclave.sh 2>/dev/null || true
            
            sed -i "/# Secrets-block/a\\
SECRET_VALUE=\$(aws secretsmanager get-secret-value --secret-id ${SECRET_ARN} --region ${REGION} | jq -r .SecretString)\\
echo \"\$SECRET_VALUE\" | jq -R '{\"${API_ENV_VAR_NAME}\": .}' > secrets.json" expose_enclave.sh
        fi

        echo "Secret fetching logic added to expose_enclave.sh"

    elif [[ "$SECRET_CHOICE" =~ ^([Ee]xisting|EXISTING)$ ]]; then
        #----------------------------------------------------
        # Use an existing secret ARN
        #----------------------------------------------------
        if [ -z "$SECRET_ARN" ]; then
            read -p "Enter the existing secret ARN: " SECRET_ARN
        else
            echo "使用预设的 SECRET_ARN 值: $SECRET_ARN"
        fi

        # Validate that the secret exists and has a value
        echo "Validating secret ARN..."
        SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --region "$REGION" 2>&1)
        if [ $? -ne 0 ]; then
            echo "Error: Failed to retrieve secret. Enter a valid secret ARN and try again. "
            echo "AWS CLI error:"
            echo "$SECRET_VALUE"
            exit 1
        fi
        
        # Extract the actual secret value from the JSON response
        SECRET_VALUE=$(echo "$SECRET_VALUE" | jq -r '.SecretString // empty')
        if [ -z "$SECRET_VALUE" ]; then
            echo "Error: Invalid secret string."
            exit 1
        fi
        echo "Secret validation successful"

        # We won't create a new secret, but we still need the instance role if we need
        # to actually read from Secrets Manager.
        ROLE_NAME="role-${FINAL_INSTANCE_NAME}"
        echo "Creating IAM role '$ROLE_NAME' for the EC2 instance..."

        cat <<EOF > trust-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

          aws iam create-role \
             --role-name "$ROLE_NAME" \
             --assume-role-policy-document file://trust-policy.json > /dev/null 2>&1

          cat <<EOF > secrets-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "$SECRET_ARN"
    }
  ]
}
EOF

          aws iam put-role-policy \
             --role-name "$ROLE_NAME" \
             --policy-name "$FINAL_INSTANCE_NAME" \
             --policy-document file://secrets-policy.json > /dev/null 2>&1

          aws iam create-instance-profile \
             --instance-profile-name "$ROLE_NAME" > /dev/null 2>&1

          aws iam add-role-to-instance-profile \
             --instance-profile-name "$ROLE_NAME" \
             --role-name "$ROLE_NAME" > /dev/null 2>&1

          IAM_INSTANCE_PROFILE_OPTION=""
        
        # Remove old references first
        if [[ "$(uname)" == "Darwin" ]]; then
          sed -i '' '/SECRET_VALUE=/d' expose_enclave.sh 2>/dev/null || true
          sed -i '' '/echo.*secrets\.json/d' expose_enclave.sh 2>/dev/null || true
        else
          sed -i '/SECRET_VALUE=/d' expose_enclave.sh 2>/dev/null || true
          sed -i '/echo.*secrets\.json/d' expose_enclave.sh 2>/dev/null || true
        fi

        echo "Inserting existing secret ARN lines into expose_enclave.sh..."

        if [[ "$(uname)" == "Darwin" ]]; then
            sed -i '' "/# Secrets-block/a\\
SECRET_VALUE=\$(aws secretsmanager get-secret-value --secret-id ${SECRET_ARN} --region ${REGION} | jq -r .SecretString)\\
echo \"\$SECRET_VALUE\" | jq -R '{\"${API_ENV_VAR_NAME}\": .}' > secrets.json" expose_enclave.sh
        else
            sed -i "/# Secrets-block/a\\
SECRET_VALUE=\$(aws secretsmanager get-secret-value --secret-id ${SECRET_ARN} --region ${REGION} | jq -r .SecretString)\\
echo \"\$SECRET_VALUE\" | jq -R '{\"${API_ENV_VAR_NAME}\": .}' > secrets.json" expose_enclave.sh
        fi

    else
        echo "Invalid choice. No secret created or used."
        IAM_INSTANCE_PROFILE_OPTION=""
        ROLE_NAME=""

        # Remove references
        if [[ "$(uname)" == "Darwin" ]]; then
          sed -i '' '/SECRET_VALUE=/d' expose_enclave.sh 2>/dev/null || true
          sed -i '' '/echo.*secrets\.json/d' expose_enclave.sh 2>/dev/null || true
        else
          sed -i '/SECRET_VALUE=/d' expose_enclave.sh 2>/dev/null || true
          sed -i '/echo.*secrets\.json/d' expose_enclave.sh 2>/dev/null || true
        fi
    fi

else
    #-----------------------------------------
    # No secret at all
    #-----------------------------------------
    IAM_INSTANCE_PROFILE_OPTION=""
    ROLE_NAME=""

    # Remove references
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' '/SECRET_VALUE=/d' expose_enclave.sh 2>/dev/null || true
        sed -i '' '/echo.*secrets\.json/d' expose_enclave.sh 2>/dev/null || true
    else
        sed -i '/SECRET_VALUE=/d' expose_enclave.sh 2>/dev/null || true
        sed -i '/echo.*secrets\.json/d' expose_enclave.sh 2>/dev/null || true
    fi
fi


#############################################################
# Create the user-data script that the instance will run
# on first boot.
#############################################################
cat <<'EOF' > user-data.sh
#!/bin/bash
# Update the instance and install Nitro Enclaves tools, Docker and other utilities
sudo yum update -y
sudo yum install -y aws-nitro-enclaves-cli-devel aws-nitro-enclaves-cli docker nano socat git make

# Add the current user to the docker group (so you can run docker without sudo)
sudo usermod -aG docker ec2-user

# Start and enable Nitro Enclaves allocator and Docker services
sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
sudo systemctl start docker && sudo systemctl enable docker
sudo systemctl enable nitro-enclaves-vsock-proxy.service
EOF

# Append endpoint configuration to the vsock-proxy YAML if endpoints were provided.
if [ -n "$ENDPOINTS" ]; then
    for ep in $ENDPOINTS; do
        echo "echo \"- {address: $ep, port: 443}\" | sudo tee -a /etc/nitro_enclaves/vsock-proxy.yaml" >> user-data.sh
    done
fi

# Continue the user-data script
cat <<EOF >> user-data.sh
# Stop the allocator so we can modify its configuration
sudo systemctl stop nitro-enclaves-allocator.service

# Adjust the enclave allocator memory (default set to 3072 MiB)
ALLOCATOR_YAML=/etc/nitro_enclaves/allocator.yaml
MEM_KEY=memory_mib
DEFAULT_MEM=3072
sudo sed -r "s/^(\s*${MEM_KEY}\s*:\s*).*/\1${DEFAULT_MEM}/" -i "${ALLOCATOR_YAML}"

# Restart the allocator with the updated memory configuration
sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service

# Restart vsock-proxy processes for various endpoints.
EOF

# Append additional vsock-proxy commands for each extra endpoint.
if [ -n "$ENDPOINTS" ]; then
    PORT=8101
    for ep in $ENDPOINTS; do
        echo "vsock-proxy $PORT $ep 443 --config /etc/nitro_enclaves/vsock-proxy.yaml &" >> user-data.sh
        PORT=$((PORT+1))
    done
fi

# Append Grafana Alloy installation 
cat <<EOF >> user-data.sh

wget -q -O gpg.key https://rpm.grafana.com/gpg.key
sudo rpm --import gpg.key
echo -e '[grafana]\nname=grafana\nbaseurl=https://rpm.grafana.com\nrepo_gpgcheck=1\nenabled=1\ngpgcheck=1\ngpgkey=https://rpm.grafana.com/gpg.key\nsslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt' | sudo tee /etc/yum.repos.d/grafana.repo
dnf update
sudo dnf install alloy -y
sudo dnf upgrade --releasever=2023.5.20240819 #(This upgrades latest ca-certifcates/nitro-cli dependencies)

# Install Grafana Agent config
sudo mkdir -p /etc/alloy

# Start Grafana Agent
sudo systemctl reload alloy
sudo systemctl start alloy

EOF


###################################################################
# Fix src/nautilus-server/run.sh to add endpoint + forwarders
###################################################################
ip=64
endpoints_config=""
for ep in $ENDPOINTS; do
    endpoints_config="${endpoints_config}echo \"127.0.0.${ip}   ${ep}\" >> /etc/hosts"$'\n'
    ip=$((ip+1))
done

echo "Adding the following endpoint configuration to src/nautilus-server/run.sh:"
echo "$endpoints_config"

# Remove any existing endpoint lines (except the first localhost line)
if [[ "$(uname)" == "Darwin" ]]; then
    # Remove only the IP mapping lines, preserving comments
    sed -i '' '/echo "127.0.0.[0-9]*   .*" >> \/etc\/hosts/d' src/nautilus-server/run.sh
    # Restore the localhost line if it was removed
    if ! grep -q "echo \"127.0.0.1   localhost\" > /etc/hosts" src/nautilus-server/run.sh; then
        sed -i '' '/# Add a hosts record/a\
echo "127.0.0.1   localhost" > /etc/hosts' src/nautilus-server/run.sh
    fi
else
    # Remove only the IP mapping lines, preserving comments
    sed -i '/echo "127.0.0.[0-9]*   .*" >> \/etc\/hosts/d' src/nautilus-server/run.sh
    # Restore the localhost line if it was removed
    if ! grep -q "echo \"127.0.0.1   localhost\" > /etc/hosts" src/nautilus-server/run.sh; then
        sed -i '/# Add a hosts record/a\echo "127.0.0.1   localhost" > /etc/hosts' src/nautilus-server/run.sh
    fi
fi

# Add the new endpoint configuration
tmp_hosts="/tmp/endpoints_config.txt"
echo "$endpoints_config" > "$tmp_hosts"

# Insert after the localhost line
if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' "/echo \"127.0.0.1   localhost\" > \/etc\/hosts/ r $tmp_hosts" src/nautilus-server/run.sh
else
    sed -i "/echo \"127.0.0.1   localhost\" > \/etc\/hosts/ r $tmp_hosts" src/nautilus-server/run.sh
fi
rm "$tmp_hosts"

ip_forwarder=64
port_forwarder=8101
traffic_config=""
for ep in $ENDPOINTS; do
    traffic_config="${traffic_config}python3 /traffic_forwarder.py 127.0.0.${ip_forwarder} 443 3 ${port_forwarder} &"$'\n'
    ip_forwarder=$((ip_forwarder+1))
    port_forwarder=$((port_forwarder+1))
done

echo "Adding the following traffic forwarder configuration to src/nautilus-server/run.sh:"
echo "$traffic_config"

# Remove any existing traffic forwarder lines
if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' '/python3 \/traffic_forwarder.py/d' src/nautilus-server/run.sh
else
    sed -i '/python3 \/traffic_forwarder.py/d' src/nautilus-server/run.sh
fi

# Add the new traffic forwarder configuration
tmp_traffic="/tmp/traffic_config.txt"
echo "$traffic_config" > "$tmp_traffic"

if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' "/# Traffic-forwarder-block/ r $tmp_traffic" src/nautilus-server/run.sh
else
    sed -i "/# Traffic-forwarder-block/ r $tmp_traffic" src/nautilus-server/run.sh
fi
rm "$tmp_traffic"

echo "updated run.sh"

############################
# 设置VPC和子网
############################
setup_vpc_subnet() {
  # 如果提供了VPC_ID，检查它是否存在
  if [ -n "$VPC_ID" ]; then
    echo "检查指定的VPC: $VPC_ID 是否存在..."
    VPC_CHECK=$(aws ec2 describe-vpcs --vpc-ids "$VPC_ID" --region "$REGION" 2>&1)
    if [ $? -ne 0 ]; then
      echo "错误: 指定的VPC不存在或无法访问。"
      echo "AWS CLI错误:"
      echo "$VPC_CHECK"
      exit 1
    fi
    echo "使用指定的VPC: $VPC_ID"
  else
    # 如果没有指定VPC_ID，检查是否有默认VPC
    echo "检查默认VPC..."
    DEFAULT_VPC=$(aws ec2 describe-vpcs --filter "Name=isDefault,Values=true" --region "$REGION" --query "Vpcs[0].VpcId" --output text)
    if [ "$DEFAULT_VPC" != "None" ] && [ -n "$DEFAULT_VPC" ]; then
      VPC_ID=$DEFAULT_VPC
      echo "使用默认VPC: $VPC_ID"
    else
      # 如果没有默认VPC，创建一个新的
      echo "没有找到默认VPC，创建新VPC..."
      VPC_ID=$(aws ec2 create-vpc --cidr-block 10.0.0.0/16 --region "$REGION" --query "Vpc.VpcId" --output text)
      echo "新建VPC: $VPC_ID"
      
      # 等待VPC创建完成
      aws ec2 wait vpc-available --vpc-ids "$VPC_ID" --region "$REGION"
      
      # 为新VPC创建互联网网关
      IGW_ID=$(aws ec2 create-internet-gateway --region "$REGION" --query "InternetGateway.InternetGatewayId" --output text)
      aws ec2 attach-internet-gateway --vpc-id "$VPC_ID" --internet-gateway-id "$IGW_ID" --region "$REGION"
      echo "互联网网关 $IGW_ID 已附加到VPC"
    fi
  fi
  
  # 查找或创建子网
  echo "查找公共子网..."
  SUBNET_ID=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --region "$REGION" --query "Subnets[0].SubnetId" --output text)
  
  if [ "$SUBNET_ID" = "None" ] || [ -z "$SUBNET_ID" ]; then
    # 获取第一个可用区
    AZ=$(aws ec2 describe-availability-zones --region "$REGION" --query "AvailabilityZones[0].ZoneName" --output text)
    echo "没有找到子网，在可用区 $AZ 创建新子网..."
    
    SUBNET_ID=$(aws ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block 10.0.1.0/24 --availability-zone "$AZ" --region "$REGION" --query "Subnet.SubnetId" --output text)
    echo "新建子网: $SUBNET_ID"
    
    # 将子网设置为公共子网(自动分配公共IP)
    aws ec2 modify-subnet-attribute --subnet-id "$SUBNET_ID" --map-public-ip-on-launch --region "$REGION"
    
    # 创建并设置路由表
    ROUTE_TABLE_ID=$(aws ec2 create-route-table --vpc-id "$VPC_ID" --region "$REGION" --query "RouteTable.RouteTableId" --output text)
    aws ec2 create-route --route-table-id "$ROUTE_TABLE_ID" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID" --region "$REGION"
    aws ec2 associate-route-table --subnet-id "$SUBNET_ID" --route-table-id "$ROUTE_TABLE_ID" --region "$REGION"
    echo "路由表已设置，允许互联网访问"
  else
    echo "使用现有子网: $SUBNET_ID"
  fi
}

# 调用VPC设置函数
setup_vpc_subnet

############################
# Create or Use Security Group
############################
SECURITY_GROUP_NAME="instance-script-sg"

# 尝试通过名称查找安全组
SECURITY_GROUP_ID=$(aws ec2 describe-security-groups \
  --region "$REGION" \
  --filters "Name=group-name,Values=$SECURITY_GROUP_NAME" "Name=vpc-id,Values=$VPC_ID" \
  --query "SecurityGroups[0].GroupId" \
  --output text 2>/dev/null)

if [ "$SECURITY_GROUP_ID" = "None" ] || [ -z "$SECURITY_GROUP_ID" ]; then
  echo "Creating security group $SECURITY_GROUP_NAME in VPC $VPC_ID..."
  SECURITY_GROUP_ID=$(aws ec2 create-security-group \
    --region "$REGION" \
    --group-name "$SECURITY_GROUP_NAME" \
    --vpc-id "$VPC_ID" \
    --description "Security group allowing SSH (22), HTTPS (443), and port 3000" \
    --query "GroupId" --output text)

  aws ec2 authorize-security-group-ingress --region "$REGION" \
    --group-id "$SECURITY_GROUP_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0

  aws ec2 authorize-security-group-ingress --region "$REGION" \
    --group-id "$SECURITY_GROUP_ID" --protocol tcp --port 443 --cidr 0.0.0.0/0

  aws ec2 authorize-security-group-ingress --region "$REGION" \
    --group-id "$SECURITY_GROUP_ID" --protocol tcp --port 3000 --cidr 0.0.0.0/0
else
  echo "Using existing security group $SECURITY_GROUP_NAME ($SECURITY_GROUP_ID)"
fi

############################
# Launch EC2 或使用现有实例
############################

if [ -n "$INSTANCE_ID" ]; then
  echo "使用指定的EC2实例: $INSTANCE_ID..."

  # 验证实例是否存在
  INSTANCE_CHECK=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" 2>&1)
  if [ $? -ne 0 ]; then
    echo "错误: 指定的实例不存在或无法访问。"
    echo "AWS CLI错误:"
    echo "$INSTANCE_CHECK"
    exit 1
  fi
  
  # 检查该实例是否支持Nitro Enclaves
  ENCLAVE_SUPPORT=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" --query "Reservations[0].Instances[0].EnclaveOptions.Enabled" --output text)
  if [ "$ENCLAVE_SUPPORT" != "True" ] && [ "$ENCLAVE_SUPPORT" != "true" ]; then
    echo "警告: 指定的实例可能不支持Nitro Enclaves功能。"
    echo "请确保该实例已启用Nitro Enclaves并已安装必要的软件。"
    read -p "是否继续使用此实例? (y/n): " CONTINUE_WITH_INSTANCE
    if [[ ! "$CONTINUE_WITH_INSTANCE" =~ ^[Yy]$ ]]; then
      echo "操作已取消。"
      exit 1
    fi
  fi

  # 获取实例的标签
  INSTANCE_NAME=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" --query "Reservations[0].Instances[0].Tags[?Key=='Name'].Value" --output text)
  if [ -z "$INSTANCE_NAME" ]; then
    INSTANCE_NAME="$FINAL_INSTANCE_NAME"
    # 给实例添加标签
    aws ec2 create-tags --resources "$INSTANCE_ID" --tags "Key=Name,Value=$INSTANCE_NAME" "Key=instance-script,Value=true" --region "$REGION"
    echo "已为实例添加标签: $INSTANCE_NAME"
  else
    echo "使用现有实例名称: $INSTANCE_NAME"
  fi
  
  # 获取实例的公共IP
  PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
  
  echo "将继续使用现有实例 $INSTANCE_ID ($INSTANCE_NAME)"
  
  # 为现有实例创建一个设置脚本，用户可以在实例内部执行
  echo "为现有实例创建setup_existing_instance.sh脚本..."
  cat user-data.sh > setup_existing_instance.sh
  chmod +x setup_existing_instance.sh
  
  echo "
echo \"===== 设置完成 =====\"
echo \"请按照以下步骤操作:\"
echo \"1. 将此脚本复制到实例 $INSTANCE_ID 上\"
echo \"2. 在实例上执行此脚本: sudo ./setup_existing_instance.sh\"
echo \"3. 按照脚本中的说明配置Nitro Enclaves环境\"
" >> setup_existing_instance.sh
  
  echo "已创建setup_existing_instance.sh脚本，您可以将其复制到实例上并执行。"
  echo "命令示例: scp setup_existing_instance.sh ec2-user@$PUBLIC_IP:~/"
  
else
  echo "Launching EC2 instance with Nitro Enclaves enabled..."

  INSTANCE_ID=$(aws ec2 run-instances \
    --region "$REGION" \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_PAIR" \
    --user-data file://user-data.sh \
    --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":200}}]' \
    --enclave-options Enabled=true \
    --security-group-ids "$SECURITY_GROUP_ID" \
    --subnet-id "$SUBNET_ID" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${FINAL_INSTANCE_NAME}},{Key=instance-script,Value=true}]" \
    --query "Instances[0].InstanceId" --output text)

  echo "Instance launched with ID: $INSTANCE_ID"

  echo "Waiting for instance $INSTANCE_ID to run..."
  aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"
  
  # 获取实例的公共IP
  PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
fi

# If an IAM role was created, associate its instance profile with the instance.
if [ -n "$ROLE_NAME" ]; then
    echo "Associating IAM instance profile $ROLE_NAME with instance $INSTANCE_ID"
    aws ec2 associate-iam-instance-profile \
        --instance-id "$INSTANCE_ID" \
        --iam-instance-profile Name="$ROLE_NAME" \
        --region "$REGION" > /dev/null 2>&1
fi

sleep 10

# Updates the ROLE_NAME in expose_enclave.sh to current role name
if [[ "$(uname)" == "Darwin" ]]; then
  sed -i '' "s/^ROLE_NAME=\".*\"/ROLE_NAME=\"$ROLE_NAME\"/" expose_enclave.sh
else
  sed -i "s/^ROLE_NAME=\".*\"/ROLE_NAME=\"$ROLE_NAME\"/" expose_enclave.sh
fi

# 确保获取公共IP地址（如果之前未获取）
if [ -z "$PUBLIC_IP" ]; then
  PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
fi

echo "[*] Commit the code generated in expose_enclave.sh and src/nautilus-server/run.sh. They will be needed when building the enclave inside the instance."

if [ -n "$INSTANCE_ID" ]; then
  echo "[*] 您正在使用现有实例 $INSTANCE_ID"
  echo "[*] 请确保该实例已正确配置Nitro Enclaves环境"
  if [ -n "$PUBLIC_IP" ]; then
    echo "[*] 实例公共IP: $PUBLIC_IP"
    echo "[*] ssh连接示例: ssh ec2-user@\"$PUBLIC_IP\""
  else
    echo "[*] 未能获取实例公共IP，请在AWS控制台查看"
  fi
else
  echo "[*] Please wait 2-3 minutes for the instance to finish the init script before sshing into it."
  if [ -n "$PUBLIC_IP" ]; then
    echo "[*] ssh inside the launched EC2 instance. e.g. \`ssh ec2-user@\"$PUBLIC_IP\"\` assuming the ssh-key is loaded into the agent."
  else
    echo "[*] ssh inside the launched EC2 instance. Check AWS console for the public IP address."
  fi
fi

echo "[*] Clone or copy the repo with the above generated code."
echo "[*] Inside repo directory: 'make' and then 'make run'"
echo "[*] Run expose_enclave.sh from within the EC2 instance to expose the enclave to the internet."