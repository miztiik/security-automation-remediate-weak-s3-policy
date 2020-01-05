#!/usr/bin/env python3

from aws_cdk import core

from remediate_weak_s3_policy.remediate_weak_s3_policy import RemediateWeakS3PolicyStack


app = core.App()
RemediateWeakS3PolicyStack(app, "security-automation-remediate-weak-s3-policy")

# Tag the stack resources
core.Tag.add(app,key="Owner",value=app.node.try_get_context('owner'))
core.Tag.add(app,key="OwnerProfile",value=app.node.try_get_context('github_profile'))
core.Tag.add(app,key="ToKnowMore",value=app.node.try_get_context('youtube_profile'))

app.synth()
