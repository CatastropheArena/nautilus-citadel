1. 创建 aws账户

2. 配置本地aws cli 
创建 IAM,配置权限
aws configure 

3. 创建key pair
aws ec2 create-key-pair --key-name "nautilus-citadel" --region us-east-1

4. 设置.env
运行sh configure_enclave.sh


```sh
Using existing security group instance-script-sg (sg-021553cccbb582d55)
Launching EC2 instance with Nitro Enclaves enabled...
Instance launched with ID: i-019a9785d246f35a3
Waiting for instance i-019a9785d246f35a3 to run...
Associating IAM instance profile role-my-enclave-810080 with instance i-019a9785d246f35a3
[*] Commit the code generated in expose_enclave.sh and src/nautilus-server/run.sh. They will be needed when building the enclave inside the instance.
[*] 您正在使用现有实例 i-019a9785d246f35a3
[*] 请确保该实例已正确配置Nitro Enclaves环境
[*] 实例公共IP: 18.232.101.175
[*] ssh连接示例: ssh ec2-user@"18.232.101.175"
[*] Clone or copy the repo with the above generated code.
[*] Inside repo directory: 'make' and then 'make run'
[*] Run expose_enclave.sh from within the EC2 instance to expose the enclave to the internet.
```
5. ssh 测试
ssh -i ~/.ssh/aws-ec2-tee-keypair.pem ec2-user@"98.81.188.33"


6. 复制 nautilus-citadel 到ec2实例
rsync -av --exclude-from=.scpignore -e "ssh -i ~/.ssh/aws-ec2-tee-keypair.pem" ../nautilus-citadel/ ec2-user@98.81.188.33:~/nautilus-citadel/

7. 运行 nautilus-citadel
cd nautilus-citadel
make && make run # this builds the enclave and run it
sh expose_enclave.sh # this exposes port 3000 to the Internet for traffic


8. 删除实例
aws ec2 describe-instances --region us-east-1 --query "Reservations[*].Instances[*].[InstanceId,State.Name,Tags]" 


aws ec2 terminate-instances --instance-ids i-046162df96ee65977 --region us-east-1