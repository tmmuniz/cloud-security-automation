# 🔐 Cloud Security Automation Lab

Fully automated Free Tier–eligible infrastructure leveraging infrastructure as code, policy-as-code, SCA, and CSPM, delivered through CI/CD pipelines and aligned with DevSecOps practices.

---

## Overview

This project covers the entire lifecycle of secure infrastructure delivery, including provisioning, configuration, policy enforcement, and continuous security assessment. The solutions used were:

- Cloud Plataform (AWS)
- Infrastructure as Code (Terraform)
- Policy as Code (OPA/Rego)
- Configuration Management (Ansible)
- Software Composition Analysis (Trivy)
- Cloud Security Posture Management (Prowler)
- CI/CD pipelines (GitHub Actions)

---

## Cloud Architecture

- EC2 instances behind an Application Load Balancer (ALB)
- Private S3 bucket for application data
- Private S3 bucket for administrative data
- IAM roles enforcing least privilege
- AWS Systems Manager (SSM) for secure access
- CloudTrail for audit logging
- Security Groups for traffic filtering

---

## Security Practices Implemented

- No SSH access (SSM Session Manager only)
- OIDC integration between GitHub Actions and AWS
- IMDSv2 enforced on EC2
- IAM least privilege applied to all roles
- Architectural Separation (Different Buckets and Roles)
- Security scanning and infrastructure validation integrated into CI/CD

---

## Security Controls

- Inbound traffic to the ALB is restricted to the allowed source public IP
- EC2 instances receive HTTP traffic only from the ALB
- EC2 instances can read and write only to the application S3 bucket
- The administrative bucket is private and restricted to Prowler, CloudTrail, and Ansible SSM transport (separated S3 prefixes)
- Security Groups allow only the required inbound traffic
- IAM roles are separated by responsibility: Terraform, Ansible, Prowler, and EC2

---

## Policy Controls

- Blocks Security Groups open to the internet (0.0.0.0/0)
- Prevents public S3 buckets and public ACLs
- Enforces S3 bucket encryption
- Enforces tagging on S3 buckets and EC2 instances

---

## Free Tier Considerations

To maximize Free Tier eligibility, the following decisions were made:

- Public IPs on EC2 instances to avoid NAT Gateway costs
- HTTP traffic to avoid DNS and certificate-related costs
- Use of the default VPC to avoid provisioning additional resources
- No Terraform state locking to avoid DynamoDB usage

**⚠️ WARNING: These configurations are not recommended for production environments**

---

## CI/CD Pipeline

### Workflow Steps

1. **Terraform** formatting and validation
2. Policy validation with **OPA/Rego**
3. Security scanning with **Trivy**
4. Terraform plan and apply
5. Configuration management with **Ansible** (via SSM)
6. Security assessment using **Prowler**
7. Report and Logs storage in S3

---

## 📁 Project Structure
.<br>
├── infra/ # Terraform code<br>
├── ansible/ # Ansible playbooks and roles<br>
├── policy/ # Rego policies<br>
├── .github/workflows/ # CI/CD pipelines<br>
└── README.md

---

## How to Deploy

### Prerequisites

- AWS account
- GitHub repository
- S3 bucket for Terraform backend (encrypted)
- OIDC configured for GitHub Actions:

| IAM Role (GitHub OIDC)  | Permission Policy |
| ------------- | ------------- |
| Terraform  | AdministratorAccess  |
| Prowler  | SecurityAudit,ViewOnlyAccess  |
| Ansible  | *Set by Terraform*  |


### Steps

1. Configure repository variables:
   - `AWS_REGION`
   - `TERRAFORM_BUCKET_NAME`
   - `ARN_OIDC_TERRAFORM_ROLE`
   - `ARN_OIDC_ANSIBLE_ROLE`
   - `ARN_OIDC_PROWLER_ROLE`
   - `ALLOWED_PUBLIC_IP_CIDR`

2. Push to the main branch will execute PLAN workflow

3. APPLY workflow will:
   - Provision the infrastructure
   - Configure instances
   - Run security checks

4. To clean all:
   - Empty the Buckets (-app and -adm)
   - Run Terraform DESTROY Workflow 

---

## Example Output

The application exposes a web page displaying:

- Instance ID, hostname, Availability Zone, region, IP, and VPC information
- Environment features overview
- S3 bucket interaction logs

Additionally:

- CloudTrail and Prowler data (securely accessible via AWS Console)

---

## Future Improvements

- Implement centralized logging with CloudWatch
- Add automated remediation (Lambda)

---

## Author

**Taynan Mina Muniz**

- Information Security Manager | DevSecOps | Terraform | AWS | GRC | ISO
- LinkedIn: (https://www.linkedin.com/in/taynan-mina-muniz-458a33102/)
- GitHub: https://github.com/tmmuniz

---
