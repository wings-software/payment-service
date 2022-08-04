# flake8: noqa
#
#  ZeroNorth Gauss Issue Normalization Service
#
#  Copyright (C) 2015-2020 ZeroNorth, Inc. All Rights Reserved.
#
#  All information, in plain text or obfuscated form, contained herein
#  is, and remains the property of ZeroNorth, Inc. and its suppliers, if any.
#  The intellectual and technical concepts contained
#  herein are proprietary to ZeroNorth, Inc. and its suppliers
#  and may be covered by U.S. and Foreign Patents,
#  patents in process, and are protected by trade secret or copyright law.
#
#  Dissemination of this information or reproduction of this material
#  is strictly forbidden unless prior written permission is obtained
#  from ZeroNorth, Inc. (support@zeronorth.io)
#
#  https://www.zeronorth.io
#
items = []

items.append(
    {
        "page": 11,
        "key": "1.1",
        "description": """This control is implemented using the AWS CloudWatch Alarm and custom Log Metric Filter defined for control 3.3 which reports if the root account is being used.""",
        "guidance": """We recommend that Root accounts should not be used and that the credentials not be shared with anyone else. As a best practice, customers should leverage IAM Groups, Roles and Users to grant access to specific AWS resources. Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html""",
        "responsibility": """Customer""",
    }
)
items.append(
    {
        "page": 13,
        "key": "1.2",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status of IAM users against this control. The Config rule DOES NOT enforce this control by enabling MFA for any of the IAM users.""",
        "guidance": """For extra security, we recommend that customers enable multi-factor authentication (MFA) for IAM users based on the compliance reported by the config rule.
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure that IAM Users with a password have MFA enabled. For remediation, refer to control 1.2 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 16,
        "key": "1.3",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status of IAM users credentials against this control. The Config rule DOES NOT enforce this control by disabling credentials.""",
        "guidance": """We recommend that unused credentials be disabled by customers based on the Compliance reported by the Config rule.
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure that credentials unused for 90 days or greater are disabled. For remediation, refer to control 1.3 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 18,
        "key": "1.4",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status of IAM users with active access keys against this control. The Config rule DOES NOT enforce this control by rotating the access keys.""",
        "guidance": """We recommend that access keys be rotated by customers based on the Compliance reported by the Config rule. Refer to IAM Best Practices at
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure that Access keys are rotated every 90 days or less. For remediation, refer to control 1.4 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 20,
        "key": "1.5",
        "description": """The Quick Start creates an AWS Managed Config Rule to check the compliance status of the policy password against these specific CIS controls. The Config rule does not enforce any security controls.""",
        "guidance": """We recommend that a strong password policy be set for IAM users.
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure that the password policy meets the controls requirements. For remediation, refer to controls 1.5 through 1.11 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 22,
        "key": "1.6",
        "description": """The Quick Start creates an AWS Managed Config Rule to check the compliance status of the policy password against these specific CIS controls. The Config rule does not enforce any security controls.""",
        "guidance": """We recommend that a strong password policy be set for IAM users.
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure that the password policy meets the controls requirements. For remediation, refer to controls 1.5 through 1.11 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 24,
        "key": "1.7",
        "description": """The Quick Start creates an AWS Managed Config Rule to check the compliance status of the policy password against these specific CIS controls. The Config rule does not enforce any security controls.""",
        "guidance": """We recommend that a strong password policy be set for IAM users.
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure that the password policy meets the controls requirements. For remediation, refer to controls 1.5 through 1.11 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 26,
        "key": "1.8",
        "description": """The Quick Start creates an AWS Managed Config Rule to check the compliance status of the policy password against these specific CIS controls. The Config rule does not enforce any security controls.""",
        "guidance": """We recommend that a strong password policy be set for IAM users.
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure that the password policy meets the controls requirements. For remediation, refer to controls 1.5 through 1.11 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 28,
        "key": "1.9",
        "description": """The Quick Start creates an AWS Managed Config Rule to check the compliance status of the policy password against these specific CIS controls. The Config rule does not enforce any security controls.""",
        "guidance": """We recommend that a strong password policy be set for IAM users.
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure that the password policy meets the controls requirements. For remediation, refer to controls 1.5 through 1.11 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 30,
        "key": "1.1",
        "description": """The Quick Start creates an AWS Managed Config Rule to check the compliance status of the policy password against these specific CIS controls. The Config rule does not enforce any security controls.""",
        "guidance": """We recommend that a strong password policy be set for IAM users.
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure that the password policy meets the controls requirements. For remediation, refer to controls 1.5 through 1.11 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 32,
        "key": "1.11",
        "description": """The Quick Start creates an AWS Managed Config Rule to check the compliance status of the policy password against these specific CIS controls. The Config rule does not enforce any security controls.""",
        "guidance": """We recommend that a strong password policy be set for IAM users.
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure that the password policy meets the controls requirements. For remediation, refer to controls 1.5 through 1.11 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 34,
        "key": "1.12",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status of root account access keys and MFA settings for root account. The Config rule DOES NOT enforce this control by changing any root account information.""",
        "guidance": """We recommend you that create an IAM user for yourself that has administrative privileges and avoid generating Access Keys for the root account.
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure that no root account access key exists. For remediation, refer to control 1.12 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 36,
        "key": "1.13",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status of root account access keys and MFA settings for root account. The Config rule DOES NOT enforce this control by changing any root account information.""",
        "guidance": """We recommend that MFA be enabled for the root account
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure MFA is enabled for root account. For remediation, refer to control 1.13 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 38,
        "key": "1.14",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status of root account access keys and MFA settings for root account. The Config rule DOES NOT enforce this control by changing any root account information.""",
        "guidance": """We recommend that MFA be enabled for the root account
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure hardware MFA is enabled for root account. For remediation, refer to control 1.14 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 40,
        "key": "1.15",
        "description": """The Quick start does not provide any implementation for this control due to the lack of APIs to automate this.""",
        "guidance": """Security Questions are highly recommended to be setup to help you recover root login access, if lost. For remediation, refer to control 1.15 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Customer""",
    }
)
items.append(
    {
        "page": 42,
        "key": "1.16",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status of IAM policies attached only to IAM Groups or Roles. The Config rule DOES NOT enforce this control by attaching IAM policies to either IAM Groups or Roles""",
        "guidance": """We recommend that you assign IAM Policies to either IAM Groups or IAM Roles to reduce the complexity of access management as the number of users grow.
If the Config rule reports NonCompliance, ensure IAM policies are attached only to Groups or Roles. For remediation, refer to control 1.16 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 44,
        "key": "1.17",
        "description": """The Quick start does not provide any implementation for this control due to the lack of APIs to automate this.""",
        "guidance": """We recommend you to enable Detailed Billing as is allows customers to get an overview of AWS activity across the whole of an account. For remediation, refer to control 1.17 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Customer""",
    }
)
items.append(
    {
        "page": 47,
        "key": "1.18",
        "description": """The Quick start does not provide any implementation for this control as these roles vary from one customer to another.""",
        "guidance": """We recommend that customers create IAM roles in a manner that no individual retains enough control over IAM to "rewrite themselves to root".
For remediation, refer to control 1.18 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Customer""",
    }
)
items.append(
    {
        "page": 59,
        "key": "1.19",
        "description": """The Quick start does not provide any implementation for this control due to the lack of APIs to automate this.""",
        "guidance": """We recommend that current contact details be maintained. AWS Uses this contact the account owner when prohibitive or suspicious activities are observed within an account.
For remediation, refer to control 1.19 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Customer""",
    }
)
items.append(
    {
        "page": 61,
        "key": "1.2",
        "description": """The Quick start does not provide any implementation for this control due to the lack of APIs to automate this.""",
        "guidance": """We recommend that the Security contact information be kept current. Specifying security-specific contact information will help ensure that security advisories sent by AWS reach the team in your organization that is best equipped to respond to them.

For remediation, refer to control 1.20 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Customer""",
    }
)
items.append(
    {
        "page": 62,
        "key": "1.21",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status of EC2 Instances which do not have an Instance Profile attached to them. The Config rule DOES NOT enforce this control by attaching Instance profiles to EC2 Instances.""",
        "guidance": """We recommend that IAM Roles be attached to an EC2 Instance to provide temporary credentials for the applications running on the EC2 Instances
Refer to IAM Best Practices at the following link:
http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

If the Config rule reports NonCompliance, ensure IAM Instance roles are used for EC2 Instances. For remediation, refer to control 1.21 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf

Note:IAM Roles can be atached to running Instances. See this documentation https://aws.amazon.com/blogs/security/new-attach-an-aws-iam-role-to-an-existing-amazon-ec2-instance-by-using-the-aws-cli/?sc_channel=sm&sc_campaign=rolesforrunninginstances&sc_publisher=tw&sc_medium=social&sc_content=read-post&sc_country=global&sc_geo=global&sc_category=ec2&sc_outcome=launch""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 65,
        "key": "1.22",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status on whether a Support role exists or not. The Config rule DOES NOT enforce this control by creating a Support role.When the "AWSSupportAccess" managed policy is not assigned to any IAM User, Role or Group the config rule will not list any resources.When the "AWSSupportAccess" managed policy is assigned to any IAM User, Role or Group the config rule will list the resources as being compliant.""",
        "guidance": """It is recommended that customers create an IAM Role to allow authorized users to manage incidents with AWS Support.

If the Config rule reports NonCompliance, ensure that atleast 1 IAM Role,User,Group has the AWSSupportAccess policy assigned to it. For remediation, refer to control 1.22 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 67,
        "key": "1.23",
        "description": """The Quick start does not provide any implementation for this control.""",
        "guidance": """It is recommended that additional steps be taken by their user upon profile creation to understand the intent of usage and storage of keys.

For remediation, refer to control 1.23 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Customer""",
    }
)
items.append(
    {
        "page": 69,
        "key": "1.24",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status on IAM Policies allowing Admin privileges. The Config rule DOES NOT enforce this control by deleting such Policies.""",
        "guidance": """It is recommended that IAM policies do not allow full administrative privileges and that the policies follow the principle of least previlige.

If the Config rule reports NonCompliance, ensure that IAM Policies provide least previlige access to AWS resources. For remediation, refer to control 1.24 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config Rule and Customer)""",
    }
)
items.append(
    {
        "page": 71,
        "key": "2.1",
        "description": """This quickstart provides customers an option to automatically configure CloudTrail in the AWS region where this Quick Start is being run. Cloudtrail is not enabled in all regions. This is because CloudTrail Logs need to be delivered to CloudWatch Logs within each region.

This control is also implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status on whether CloudTrail is enabled in all regions. The Config rule DOES NOT enforce this control by enabling CloudTrail in all regions.""",
        "guidance": """This quickstart provides customers an option to automatically configure CloudTrail in the AWS region where this Quick Start is being run. AWS accounts which do not have Cloudtrail configured, should choose this option for the CIS Cloudformation template to execute successfully.

If the Config rule reports NonCompliance, customers can choose to enable Cloudtrail in all regions and configure CloudWatch log delivery. For remediation, refer to control 2.1 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Cloudformation template, Config rule and Customer)""",
    }
)
items.append(
    {
        "page": 73,
        "key": "2.2",
        "description": """This quickstart enables Cloudtrail log file validation when customers choose the to automatically configure CloudTrail via the template.

This control is also implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status on whether CloudTrail log file validation is enabled. The Config rule DOES NOT enforce this control by enabling CloudTrail log file validation.""",
        "guidance": """If the Config rule reports NonCompliance, ensure Cloudtrail log file validation is enabled. For remediation, refer to control 2.2 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Cloudformation template, Config rule and Customer)""",
    }
)
items.append(
    {
        "page": 75,
        "key": "2.3",
        "description": """This quickstart ensures that S3 Bucket for Cloudtrail is not publicly accessible when customers choose to automatically configure Cloudtrail via the template.

This control is also implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status on whether CloudTrail log file S3 Bucket is publicly accessible. The Config rule DOES NOT enforce this control by changing S3 Bucket ACLs.""",
        "guidance": """If the Config rule reports NonCompliance, ensure S3 Bucket configured for Cloudtrail to log to is not publicly accessible . For remediation, refer to control 2.3 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Cloudformation template, Config rule and Customer)""",
    }
)
items.append(
    {
        "page": 77,
        "key": "2.4",
        "description": """This quickstart ensures that Cloudtrail trails are integrated with CloudWatch Logs when customers choose to automatically configure Cloudtrail via the template.

This control is also implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status on whether CloudTrail logs are integrated with CloudWatch logs. The Config rule DOES NOT enforce this control by configuring CloudTrail to deliver logs to CloudWatch Logs.""",
        "guidance": """If the Config rule reports NonCompliance, ensure that Cloudtrail trails are integrated with Cloudwatch logs. For remediation, refer to control 2.4 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Cloudformation template, Config rule and Customer)""",
    }
)
items.append(
    {
        "page": 80,
        "key": "2.5",
        "description": """This quickstart provides customers an option to automatically configure Config at a regional level via the template.""",
        "guidance": """This quickstart provides customers an option to automatically configure AWS Config at a regional level. Customer AWS accounts which do not have Config configured, should choose this option for the CIS Cloudformation template to execute successfully.

For manual remediation, refer to control 2.5 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Cloudformation Template and Customer)""",
    }
)
items.append(
    {
        "page": 82,
        "key": "2.6",
        "description": """This quickstart ensures that S3 bucket access logging is enabled on the Cloudtrail S3 bucket when customers choose to automatically configure Cloudtrail via the template.

This control is also implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status on whether all S3 Buckets have logging enabled. The Config rule DOES NOT enforce this control by configuring logging on any S3 bucket.""",
        "guidance": """It is recommended that Logging be enabled for all S3 Buckets. Configuring logs to be placed in a separate bucket allows access to log information which can be useful in security and incident response workflows.

If the Config rule reports NonCompliance, enable Cloudtrail S3 bucket access logging. For remediation, refer to control 2.6 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Cloudformation template, Config rule and Customer)""",
    }
)
items.append(
    {
        "page": 84,
        "key": "2.7",
        "description": """This quickstart ensures that Cloudtrail logs are encrypted at rest using KMS CMKs when customers choose to automatically configure Cloudtrail via the template.

This control is also implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status on whether CloudTrail logs are encrypted . The Config rule DOES NOT enforce this control by enabling CloudTrail log file validation.""",
        "guidance": """Configuring CloudTrail to use SSE-KMS provides additional confidentiality controls on log data as a given user must have S3 read permission on the corresponding log bucket and must be granted decrypt permission by the CMK policy.

If the Config rule reports NonCompliance, ensure Cloudtrail logs are encrypted at rest using KMS CMKs. For remediation, refer to control 2.7 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Cloudformation template, Config rule and Customer)""",
    }
)
items.append(
    {
        "page": 86,
        "key": "2.8",
        "description": """This control is implemented as a Config Rule backed by a custom Lambda function. The Config Rule reports back the compliance status on whether the rotation for any CMKs is enabled. The Config rule DOES NOT enforce this control by enabling CMKs rotation.""",
        "guidance": """It is recommended to rotate encryption keys to reduce the potential impact of a compromised key as data encrypted with a new key cannot be accessed with a previous key that may have been exposed.

If the Config rule reports NonCompliance, ensure rotation of customer created CMKs are enabled. For remediation, refer to control 2.8 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config rule and Customer)""",
    }
)
items.append(
    {
        "page": 88,
        "key": "3.1",
        "description": """The Quick Start creates an AWS CloudWatch Alarm and a custom Log Metric Filter to report on multiple unauthorized action or login attempts.""",
        "guidance": """It is recommended that customers monitor unauthorized API calls which will help reveal application errors and may reduce time to detect malicious activity.""",
        "responsibility": """Shared (CloudWatch Alarm and Customer)""",
    }
)
items.append(
    {
        "page": 91,
        "key": "3.2",
        "description": """The Quick Start creates an AWS CloudWatch Alarm and a custom Log Metric Filter to report on Management Console logins without MFA.""",
        "guidance": """It is recommended that customers monitor for single-factor console logins. This will increase visibility into accounts that are not protected by MFA.""",
        "responsibility": """Shared (CloudWatch Alarm and Customer)""",
    }
)
items.append(
    {
        "page": 94,
        "key": "3.3",
        "description": """The Quick Start creates an AWS CloudWatch Alarm and a custom Log Metric Filter to report if the root account is used.""",
        "guidance": """It is recommended that customers monitor for root account logins which will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it.""",
        "responsibility": """Shared (CloudWatch Alarm and Customer)""",
    }
)
items.append(
    {
        "page": 97,
        "key": "3.4",
        "description": """The Quick Start creates an AWS CloudWatch Rule that matches incoming CloudWatch Events for IAM policy changes and publishes the changes to an SNS topic.""",
        "guidance": """It is recommended that customers monitor changes to IAM policies which will help ensure authentication and authorization controls remain intact.""",
        "responsibility": """Shared (CloudWatch Rule and Customer)""",
    }
)
items.append(
    {
        "page": 100,
        "key": "3.5",
        "description": """The Quick Start creates an AWS CloudWatch Rule that matches incoming CloudWatch Events for CloudTrail changes and publishes the changes to an SNS topic.""",
        "guidance": """It is recommended that customers monitor changes to CloudTrail's configuration which will help ensure sustained visibility to activities performed in the AWS account.""",
        "responsibility": """Shared (CloudWatch Rule and Customer)""",
    }
)
items.append(
    {
        "page": 103,
        "key": "3.6",
        "description": """The Quick Start creates an AWS CloudWatch Alarm and a custom Log Metric Filter to report if there are multiple management console logins failures.""",
        "guidance": """It is recommended that customers monitor failed console logins. This may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation.""",
        "responsibility": """Shared (CloudWatch Alarm and Customer)""",
    }
)
items.append(
    {
        "page": 106,
        "key": "3.7",
        "description": """The Quick Start creates an AWS CloudWatch Alarm and a custom Log Metric Filter to report if customer created CMKs get disabled or scheduled for deletion.""",
        "guidance": """It is recommended that customers monitor deletion or disabling of CMKs. Data encrypted with disabled or deleted keys will no longer be accessible.""",
        "responsibility": """Shared (CloudWatch Alarm and Customer)""",
    }
)
items.append(
    {
        "page": 108,
        "key": "3.8",
        "description": """The Quick Start creates an AWS CloudWatch Rule that matches incoming CloudWatch Events for S3 bucket policy changes and publishes the changes to an SNS topic.""",
        "guidance": """It is recommended that customers monitor changes to S3 bucket policies to reduce time to detect and correct permissive policies on sensitive S3 buckets.""",
        "responsibility": """Shared (CloudWatch Rule and Customer)""",
    }
)
items.append(
    {
        "page": 111,
        "key": "3.9",
        "description": """The Quick Start creates an AWS CloudWatch Rule that matches incoming CloudWatch Events for Config changes and publishes the changes to an SNS topic.""",
        "guidance": """It is recommended that customers monitor changes to AWS Config configuration which will help ensure sustained visibility of configuration items within the AWS account.""",
        "responsibility": """Shared (CloudWatch Rule and Customer)""",
    }
)
items.append(
    {
        "page": 114,
        "key": "3.1",
        "description": """The Quick Start creates an AWS CloudWatch Rule that matches incoming CloudWatch Events for security groups changes and publishes the changes to an SNS topic.""",
        "guidance": """It is recommended that customers monitor changes to security group which will help ensure that resources and services are not unintentionally exposed.""",
        "responsibility": """Shared (CloudWatch Rule and Customer)""",
    }
)
items.append(
    {
        "page": 117,
        "key": "3.11",
        "description": """The Quick Start creates an AWS CloudWatch Rule that matches incoming CloudWatch Events for network access control lists changes and publishes the changes to an SNS topic.""",
        "guidance": """It is recommended that customers monitor changes to NACLs to help ensure that AWS resources and services are not unintentionally exposed.""",
        "responsibility": """Shared (CloudWatch Rule and Customer)""",
    }
)
items.append(
    {
        "page": 120,
        "key": "3.12",
        "description": """The Quick Start creates an AWS CloudWatch Rule that matches incoming CloudWatch Events for network gateways, route tables and VPC changes and publishes the changes to an SNS topic.""",
        "guidance": """It is recommended that customers monitor changes to network gateways which will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path.
Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path.Monitoring changes to VPC configuration will help ensure that all VPCs remain intact.""",
        "responsibility": """Shared (CloudWatch Rule and Customer)""",
    }
)
items.append(
    {
        "page": 123,
        "key": "3.13",
        "description": """The Quick Start creates an AWS CloudWatch Rule that matches incoming CloudWatch Events for network gateways, route tables and VPC changes and publishes the changes to an SNS topic.""",
        "guidance": """It is recommended that customers monitor changes to network gateways which will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path.
Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path.Monitoring changes to VPC configuration will help ensure that all VPCs remain intact.""",
        "responsibility": """Shared (CloudWatch Rule and Customer)""",
    }
)
items.append(
    {
        "page": 126,
        "key": "3.14",
        "description": """The Quick Start creates an AWS CloudWatch Rule that matches incoming CloudWatch Events for network gateways, route tables and VPC changes and publishes the changes to an SNS topic.""",
        "guidance": """It is recommended that customers monitor changes to network gateways which will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path.
Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path.Monitoring changes to VPC configuration will help ensure that all VPCs remain intact.""",
        "responsibility": """Shared (CloudWatch Rule and Customer)""",
    }
)
items.append(
    {
        "page": 129,
        "key": "3.15",
        "description": """The Quick start does not provide any implementation for this control.""",
        "guidance": """"Appropriate subscribers" is subjective to customer's AWS environments. However, we recommend that customers review the subscriber topics which will help ensure that only expected recipients receive information published to SNS topics.""",
        "responsibility": """Customer""",
    }
)
items.append(
    {
        "page": 131,
        "key": "4.1",
        "description": """This control is implemented as an AWS Managed Config Rule to report back the compliance status on whether security groups allow ingress from 0.0.0.0/0 to port 22. The Config rule DOES NOT enforce this control by restricting security groups ingress traffic from 0.0.0.0/0 to port 22.""",
        "guidance": """It is recommended that customers remove unfettered connectivity to remote console services, such as SSH, reduces a server's exposure to risk.

If the Config rule reports NonCompliance, ensure no security groups allow Ingress from 0.0.0.0/0 to port 22. For remediation, refer to control 4.1 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config rule and Customer)""",
    }
)
items.append(
    {
        "page": 133,
        "key": "4.2",
        "description": """This control is implemented as an AWS Managed Config Rule to report back the compliance status on whether security groups allow ingress from 0.0.0.0/0 to port 3389. The Config rule DOES NOT enforce this control by restricting security groups ingress traffic from 0.0.0.0/0 to port 3389.""",
        "guidance": """It is recommended that customers remove unfettered connectivity to remote console services, such as RDP, reduces a server's exposure to risk.

If the Config rule reports NonCompliance, ensure no security groups allow Ingress from 0.0.0.0/0 to port 3389. For remediation, refer to control 4.2 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config rule and Customer)""",
    }
)
items.append(
    {
        "page": 144,
        "key": "4.3",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status on whether VPC Flow Logging is enabled. The Config rule DOES NOT enforce this control by enabling VPC Flow Logging.""",
        "guidance": """It is recommended to have VPC Flow Logs enabled to provide visibility into network traffic that traverses the VPC and to detect anomalous traffic or insight during security workflows.

If the Config rule reports NonCompliance, ensure VPC Flow logging is enabled in all VPCs. For remediation, refer to control 4.3 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config rule and Customer)""",
    }
)
items.append(
    {
        "page": 137,
        "key": "4.4",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status on whether the default security groups restrict all traffic. The Config rule DOES NOT enforce this control by configuring the default security groups.""",
        "guidance": """It is recommended to configure all VPC default security groups to restrict all traffic. This will encourage least privilege security group development and mindful placement of AWS resources into security groups which will in-turn reduce the exposure of those resources.

If the Config rule reports NonCompliance, ensure that the default security group of every VPC restricts all traffic. For remediation, refer to control 4.4 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config rule and Customer)""",
    }
)
items.append(
    {
        "page": 140,
        "key": "4.5",
        "description": """This control is implemented as a Config rule backed by a custom lambda function. The config rule reports back the compliance status on whether the VPC routing tables are configured with "least access". The Config rule DOES NOT enforce this control by configuring routing tables for VPC peering.""",
        "guidance": """Being highly selective in peering routing tables is a very effective way of minimizing the impact of breach as resources outside of these routes are inaccessible to the peered VPC.

If the Config rule reports NonCompliance, ensure that the routing tables for VPC peering are "least access". For remediation, refer to control 4.5 in the document https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf""",
        "responsibility": """Shared (Config rule and Customer)""",
    },
)
