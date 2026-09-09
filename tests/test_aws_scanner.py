from agentshield.scanners.aws import AwsSecurityScanner


class FakeSTS:
    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/scanner", "UserId": "AIDATEST"}


class FakeIAM:
    def list_roles(self, **kwargs):
        return {
            "Roles": [
                {
                    "Path": "/ai/", "RoleName": "BedrockAgentRole",
                    "Arn": "arn:aws:iam::123456789012:role/ai/BedrockAgentRole",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}],
                    },
                },
                {
                    "Path": "/", "RoleName": "SafeReadRole",
                    "Arn": "arn:aws:iam::123456789012:role/SafeReadRole",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
                    },
                },
            ],
            "IsTruncated": False,
        }

    def list_attached_role_policies(self, RoleName, **kwargs):
        if RoleName == "BedrockAgentRole":
            return {"AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}], "IsTruncated": False}
        return {"AttachedPolicies": [], "IsTruncated": False}

    def get_policy(self, PolicyArn):
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):
        return {"PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}}

    def list_role_policies(self, RoleName, **kwargs):
        if RoleName == "BedrockAgentRole":
            return {"PolicyNames": ["AgentInline"], "IsTruncated": False}
        return {"PolicyNames": ["SafeInline"], "IsTruncated": False}

    def get_role_policy(self, RoleName, PolicyName):
        if RoleName == "BedrockAgentRole":
            return {"PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "secretsmanager:GetSecretValue"], "Resource": "*"}]}}
        return {"PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::approved-bucket/*"}]}}

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1}}


class FakeCloudTrail:
    def describe_trails(self, includeShadowTrails=False):
        return {"trailList": [{"Name": "org-trail", "TrailARN": "arn:trail", "IsMultiRegionTrail": True}]}
    def get_trail_status(self, Name):
        return {"IsLogging": True}


class FakeGuardDuty:
    def list_detectors(self): return {"DetectorIds": ["detector-1"]}


class FakeConfig:
    def describe_configuration_recorders(self): return {"ConfigurationRecorders": [{"name": "default"}]}
    def describe_configuration_recorder_status(self): return {"ConfigurationRecordersStatus": [{"name": "default", "recording": True}]}


class FakeS3Control:
    def get_public_access_block(self, AccountId):
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}


class FakeEC2:
    def get_ebs_encryption_by_default(self): return {"EbsEncryptionByDefault": True}


class FakeSecurityHub:
    def describe_hub(self): return {"HubArn": "arn:hub"}


class FakeSession:
    region_name = "ap-south-1"
    clients = {
        "sts": FakeSTS(), "iam": FakeIAM(), "cloudtrail": FakeCloudTrail(),
        "guardduty": FakeGuardDuty(), "config": FakeConfig(), "s3control": FakeS3Control(),
        "ec2": FakeEC2(), "securityhub": FakeSecurityHub(),
    }
    def client(self, service, **kwargs): return self.clients[service]


def test_aws_scanner_finds_dangerous_ai_role():
    result = AwsSecurityScanner(session=FakeSession()).scan()
    ids = {f.rule_id for f in result.findings}
    assert "AS-AWS-IAM-010" in ids
    assert "AS-AWS-IAM-013" in ids
    assert "AS-AWS-IAM-015" in ids
    assert "AS-AWS-DATA-001" in ids
    roles = result.metadata["role_assessments"]
    risky = next(r for r in roles if r["name"] == "BedrockAgentRole")
    safe = next(r for r in roles if r["name"] == "SafeReadRole")
    assert risky["candidate_ai_role"] is True
    assert risky["blast_radius"] == "CRITICAL"
    assert safe["blast_radius"] == "LOW"


def test_aws_ai_only_filter():
    result = AwsSecurityScanner(session=FakeSession(), ai_only=True, role_pattern="Bedrock*").scan()
    roles = result.metadata["role_assessments"]
    assert len(roles) == 1
    assert roles[0]["name"] == "BedrockAgentRole"
