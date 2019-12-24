#!/usr/bin/env python3

from aws_cdk import core

from remediate_weak_s3_policy.remediate_weak_s3_policy import RemediateWeakS3PolicyStack


app = core.App()
RemediateWeakS3PolicyStack(app, "security-automation-remediate-weak-s3-policy")

app.synth()
