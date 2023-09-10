terraform {
  required_providers {
    aws = {
      version = "<= 5.15.0"
      source = "hashicorp/aws"
    }
  }
}

locals {
  cluster_name = "nnewc-tf"
  aws_region   = "us-gov-west-1"

  rke2_version = "v1.24.16+rke2r1"
  tags = {
    "terraform" = "true",
    "env"       = "nnewc-tf",
  }
}

data "aws_ami" "rhel7" {
  most_recent = true
  owners      = ["219670896067"] # owner is specific to aws gov cloud

  filter {
    name   = "name"
    values = ["RHEL-7*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

data "aws_ami" "rhel8" {
  most_recent = true
  owners      = ["219670896067"] # owner is specific to aws gov cloud

  filter {
    name   = "name"
    values = ["RHEL-8*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# data "aws_ami" "centos7" {
#   most_recent = true
#   owners      = ["345084742485"] # owner is specific to aws gov cloud

#   filter {
#     name   = "name"
#     values = ["CentOS Linux 7 x86_64 HVM EBS*"]
#   }

#   filter {
#     name   = "architecture"
#     values = ["x86_64"]
#   }
# }

# data "aws_ami" "centos8" {
#   most_recent = true
#   owners      = ["345084742485"] # owner is specific to aws gov cloud

#   filter {
#     name   = "name"
#     values = ["CentOS Linux 8 x86_64 HVM EBS*"]
#   }

#   filter {
#     name   = "architecture"
#     values = ["x86_64"]
#   }
# }

# Key Pair
resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "ssh_pem" {
  filename        = "${local.cluster_name}.pem"
  content         = tls_private_key.ssh.private_key_pem
  file_permission = "0600"
}

# resource "aws_ec2_host" "jumpbox" {
#   instance_type     = "t3.small"
#   availability_zone = "us-gov-west-1"
# }

#
# Network
#
# module "vpc" {
#   source = "terraform-aws-modules/vpc/aws"

#   name = "${local.cluster_name}"
#   cidr = "10.0.0.0/16"

#   azs             = ["${local.aws_region}a", "${local.aws_region}b", "${local.aws_region}c"]
#   public_subnets  = ["10.0.3.0/24"]
#   # private_subnets = ["10.88.101.0/24", "10.88.102.0/24", "10.88.103.0/24"]

#   enable_nat_gateway   = false
#   single_nat_gateway   = false
#   enable_vpn_gateway   = false
#   enable_dns_hostnames = true
#   enable_dns_support   = true

#   # Add in required tags for proper AWS CCM integration
#   public_subnet_tags = merge({
#     "kubernetes.io/cluster/${module.rke2.cluster_name}" = "shared"
#     "kubernetes.io/role/elb"                            = "1"
#   }, local.tags)

#   private_subnet_tags = merge({
#     "kubernetes.io/cluster/${module.rke2.cluster_name}" = "shared"
#     "kubernetes.io/role/internal-elb"                   = "1"
#   }, local.tags)

#   tags = merge({
#     "kubernetes.io/cluster/${module.rke2.cluster_name}" = "shared"
#   }, local.tags)



# }

data "aws_vpc" "owner_vpc" {
  id = "vpc-0cd2fd249b9961ac2"
}

#
# Server
#
module "rke2" {
  source = "../.."

  cluster_name = local.cluster_name
  vpc_id       = data.aws_vpc.owner_vpc.id
  subnets      = ["subnet-05894523ac9876db3", "subnet-057c297a02b75f332", "subnet-03844f6573f40febd"]

  ami                   = data.aws_ami.rhel8.id
  ssh_authorized_keys   = [tls_private_key.ssh.public_key_openssh]
  instance_type         = "t3a.medium"
  controlplane_internal = false # Note this defaults to best practice of true, but is explicitly set to public for demo purposes
  servers               = 1
  associate_public_ip_address = true
  # Enable AWS Cloud Controller Manager
  enable_ccm = true
  
  rke2_version = local.rke2_version
  rke2_config = <<-EOT
write-kubeconfig-mode: 644
secrets-encryption: true
profile: cis-1.6
kube-controller-manager-arg:
  - tls-min-version=VersionTLS12
  - tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
kube-scheduler-arg:
  - tls-min-version=VersionTLS12
  - tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
kube-apiserver-arg: 
  - tls-min-version=VersionTLS12
  - tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  - authorization-mode=RBAC,Node
  - anonymous-auth=false
  - audit-policy-file=/etc/rancher/rke2/audit-policy.yaml
  - audit-log-mode=blocking-strict
kubelet-arg:
  - protect-kernel-defaults=true
  - streaming-connection-idle-timeout=5m
node-taint: 
- CriticalAddonsOnly=true:NoExecute
node-label:
  - "name=server"
  - "os=rhel8"
EOT

  tags = local.tags

  extra_cloud_config_config = <<-EOT
package_update: true
packages:
- vim
- bash-completion
- jq
runcmd:
- useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U
- systemctl stop nm-cloud-setup.service
- systemctl disable nm-cloud-setup.service
- systemctl stop nm-cloud-setup.timer
- systemctl disable nm-cloud-setup.timer
- sysctl -p /etc/sysctl.d/90-kubelet.conf
- sudo systemctl disable firewalld
- sudo systemctl stop firewalld
- modprobe br_netfilter
- modprobe overlay
  # Kernel modules required by istio-init, required for selinux enforcing instances using istio-init
- modprobe xt_REDIRECT
- modprobe xt_owner
- modprobe xt_statistic
- sysctl -w net.ipv4.ip_forward=1
- sysctl -w net.bridge.bridge-nf-call-iptables=1
- sysctl -w fs.inotify.max_user_instances=8192
- sysctl -w fs.inotify.max_user_watches=524288
- sysctl -w user.max_user_namespaces=28633
- sysctl -p /etc/sysctl.d/90-kubelet.conf
  # Tune vm sysctl for elasticsearch
- sysctl -w vm.max_map_count=524288
- mkdir -p /var/run/istio-cni && semanage fcontext -a -t container_file_t /var/run/istio-cni && restorecon -v /var/run/istio-cni
write_files:
# Kernel modules required by kubernetes and istio-init, required for selinux enforcing instances using istio-init
- content: |
    br_netfilter
    overlay
    xt_REDIRECT
    xt_owner
    xt_statistic 
  owner: root:root
  path: /etc/modules
  permissions: '0644'
# Prevent Canal Problems
- content: |
    [keyfile]
    unmanaged-devices=interface-name:cali*;interface-name:flannel*
  owner: root:root
  path: /etc/NetworkManager/conf.d/rke2-canal.conf
  permissions: '0644'
# file watchers
- content: |
    sysctl fs.inotify.max_user_instances=8192
    sysctl fs.inotify.max_user_watches=524288
  owner: root:root
  path: /etc/sysctl.d/98-rke2-fs.conf
  permissions: '0644'
# enable bridged traffic
- content: |
    net.bridge.bridge-nf-call-iptables  = 1
    net.bridge.bridge-nf-call-ip6tables = 1
    net.ipv4.ip_forward                 = 1
  owner: root:root
  path: /etc/sysctl.d/99-rke2-iptables.conf
  permissions: '0644'
- content: |
    kernel.panic = 10
    kernel.panic_on_oops = 1
    vm.overcommit_memory = 1
    vm.panic_on_oom = 0
  path: /etc/sysctl.d/90-kubelet.conf
EOT
}

#
# Generic agent pool
#
module "agents" {
  source = "../../modules/agent-nodepool"

  name    = "generic"
  vpc_id  = data.aws_vpc.owner_vpc.id
  subnets = ["subnet-05894523ac9876db3", "subnet-057c297a02b75f332", "subnet-03844f6573f40febd"] # Note: Public subnets used for demo purposes, this is not recommended in production

  ami                 = data.aws_ami.rhel8.id
  ssh_authorized_keys = [tls_private_key.ssh.public_key_openssh]
  spot                = true
  //asg                 = { min : 1, max : 10, desired : 2, termination_policies = [  ] }
  instance_type       = "t3a.xlarge"
  associate_public_ip_address = true

  # Enable AWS Cloud Controller Manager and Cluster Autoscaler
  enable_ccm        = true
  enable_autoscaler = true
  rke2_version = local.rke2_version
  rke2_config = <<-EOT
profile: cis-1.6
kubelet-arg:
  - protect-kernel-defaults=true
  - streaming-connection-idle-timeout=5m
  - authorization-mode=Webhook
node-label:
  - "name=generic"
  - "os=rhel8"
EOT

  extra_cloud_config_config = <<-EOT
package_update: true
packages:
- vim
- bash-completion
- jq
runcmd:
- useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U
- systemctl stop nm-cloud-setup.service
- systemctl disable nm-cloud-setup.service
- systemctl stop nm-cloud-setup.timer
- systemctl disable nm-cloud-setup.timer
- sudo systemctl disable firewalld
- sudo systemctl stop firewalld
- modprobe br_netfilter
- modprobe overlay
  # Kernel modules required by istio-init, required for selinux enforcing instances using istio-init
- modprobe xt_REDIRECT
- modprobe xt_owner
- modprobe xt_statistic
- sysctl -w net.ipv4.ip_forward=1
- sysctl -w net.bridge.bridge-nf-call-iptables=1
- sysctl -w fs.inotify.max_user_instances=8192
- sysctl -w fs.inotify.max_user_watches=524288
- sysctl -w user.max_user_namespaces=28633
- sysctl -p /etc/sysctl.d/90-kubelet.conf
  # Tune vm sysctl for elasticsearch
- sysctl -w vm.max_map_count=524288
- mkdir -p /var/run/istio-cni && semanage fcontext -a -t container_file_t /var/run/istio-cni && restorecon -v /var/run/istio-cni
write_files:
# Kernel modules required by kubernetes and istio-init, required for selinux enforcing instances using istio-init
- content: |
    br_netfilter
    overlay
    xt_REDIRECT
    xt_owner
    xt_statistic 
  owner: root:root
  path: /etc/modules
  permissions: '0644'
# Prevent Canal Problems
- content: |
    [keyfile]
    unmanaged-devices=interface-name:cali*;interface-name:flannel*
  owner: root:root
  path: /etc/NetworkManager/conf.d/rke2-canal.conf
  permissions: '0644'
# file watchers
- content: |
    sysctl fs.inotify.max_user_instances=8192
    sysctl fs.inotify.max_user_watches=524288
  owner: root:root
  path: /etc/sysctl.d/98-rke2-fs.conf
  permissions: '0644'
# enable bridged traffic
- content: |
    net.bridge.bridge-nf-call-iptables  = 1
    net.bridge.bridge-nf-call-ip6tables = 1
    net.ipv4.ip_forward                 = 1
  owner: root:root
  path: /etc/sysctl.d/99-rke2-iptables.conf
  permissions: '0644'
- content: |
    kernel.panic = 10
    kernel.panic_on_oops = 1
    vm.overcommit_memory = 1
    vm.panic_on_oom = 0
  path: /etc/sysctl.d/90-kubelet.conf
EOT

  cluster_data = module.rke2.cluster_data

  tags = local.tags
}

# For demonstration only, lock down ssh access in production
resource "aws_security_group_rule" "quickstart_ssh" {
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = module.rke2.cluster_data.cluster_sg
  type              = "ingress"
  cidr_blocks       = ["0.0.0.0/0"]
}

# Generic outputs as examples
output "rke2" {
  value = module.rke2
}

# Example method of fetching kubeconfig from state store, requires aws cli and bash locally
resource "null_resource" "kubeconfig" {
  depends_on = [module.rke2]

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    command     = "aws s3 cp ${module.rke2.kubeconfig_path} rke2.yaml"
  }
}