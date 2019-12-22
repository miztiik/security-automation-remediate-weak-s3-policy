#!/usr/bin/env python3

from aws_cdk import core

from security_incident_response_remediate_weak_s3_policy.security_incident_response_remediate_weak_s3_policy_stack import SecurityIncidentResponseRemediateWeakS3PolicyStack


app = core.App()
SecurityIncidentResponseRemediateWeakS3PolicyStack(app, "security-incident-response-remediate-weak-s3-policy")

app.synth()
