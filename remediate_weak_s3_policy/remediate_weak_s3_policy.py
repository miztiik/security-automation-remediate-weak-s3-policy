import json

from aws_cdk import aws_cloudtrail as _cloudtrail
from aws_cdk import aws_events as _events
from aws_cdk import aws_events_targets as _targets
from aws_cdk import aws_iam as _iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_logs as _logs
from aws_cdk import aws_s3 as _s3
from aws_cdk import aws_stepfunctions as _sfn
from aws_cdk import aws_stepfunctions_tasks as _tasks
from aws_cdk import core

from custom_resource.iam_user_tagger_cdk import iam_user_tagger
from custom_resource.random_string_generator_cdk import random_string_generator

class global_args:
    '''
    Helper to define global statics
    '''
    OWNER                       = "MystiqueInfoSecurity"
    ENVIRONMENT                 = "production"
    SOURCE_INFO                 = "https://github.com/miztiik/security-automation-remediate-weak-s3-policy"


class RemediateWeakS3PolicyStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Defines an AWS Lambda resource
        with open("lambda_src/is_policy_permissive.py", encoding="utf8") as fp:
            is_policy_permissive_fn_handler_code = fp.read()

        is_policy_permissive_fn = _lambda.Function(
            self,
            id='policyStrengthCheckerFn',
            function_name="is_policy_permissive_fn",
            runtime=_lambda.Runtime.PYTHON_3_7,
            code=_lambda.InlineCode(is_policy_permissive_fn_handler_code),
            # code=_lambda.Code.asset("lambda_src/is_policy_permissive.py"),
            # code=_lambda.Code.asset('lambda_src'),
            # code=_lambda.InlineCode(code_body),
            handler='index.lambda_handler',
            timeout=core.Duration.seconds(5)
        )
        core.Tag.add(is_policy_permissive_fn, key="Owner",value=global_args.OWNER)
        core.Tag.add(is_policy_permissive_fn, key="ToKnowMore",value=global_args.SOURCE_INFO)

        # Defines an AWS Lambda resource
        with open("lambda_src/get_previous_bucket_policy.py", encoding="utf8") as fp:
            get_previous_bucket_policy_fn_handler_code = fp.read()
        get_previous_bucket_policy_fn = _lambda.Function(
            self,
            id='getPreviousBucketPolicyFn',
            function_name="get_previous_bucket_policy_fn",
            runtime=_lambda.Runtime.PYTHON_3_7,
            code=_lambda.InlineCode(get_previous_bucket_policy_fn_handler_code),
            handler='index.lambda_handler',
            timeout=core.Duration.seconds(5)
        )
        core.Tag.add(get_previous_bucket_policy_fn,key="Owner",value=global_args.OWNER)
        core.Tag.add(get_previous_bucket_policy_fn, key="ToKnowMore",value=global_args.SOURCE_INFO)

        get_previous_bucket_policy_fn_perms=_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            resources=[
                "*",
                ],
            actions=[
                "config:GetResourceConfigHistory",
            ]
        )
        get_previous_bucket_policy_fn_perms.sid="GetPreviouBucketPolicy"
        get_previous_bucket_policy_fn.add_to_role_policy( get_previous_bucket_policy_fn_perms )


        # Defines an AWS Lambda resource
        with open("lambda_src/put_policy.py", encoding="utf8") as fp:
            put_policy_fn_handler_code = fp.read()
        put_policy_fn = _lambda.Function(
            self,
            id='putPolicyFn',
            function_name="put_policy_fn",
            runtime=_lambda.Runtime.PYTHON_3_7,
            code=_lambda.InlineCode(put_policy_fn_handler_code),
            handler='index.lambda_handler',
            timeout=core.Duration.seconds(5)
        )
        core.Tag.add(put_policy_fn,key="Owner",value=global_args.OWNER)
        core.Tag.add(put_policy_fn, key="ToKnowMore",value=global_args.SOURCE_INFO)

        put_policy_fn_perms=_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            resources=[
                "arn:aws:s3:::*",
                ],
            actions=[
                "s3:PutBucketPolicy",
                "s3:DeleteBucketPolicy",
            ]
        )
        put_policy_fn_perms.sid="PutBucketPolicy"
        put_policy_fn.add_to_role_policy( put_policy_fn_perms )

        # Ref: https://docs.aws.amazon.com/cdk/api/latest/docs/aws-stepfunctions-readme.html
        ###############################################################################
        ################# STEP FUNCTIONS EXPERIMENTAL CODE - UNSTABLE #################
        ###############################################################################

        is_new_policy_permissive_task = _sfn.Task(self, "isNewPolicyPermissive",
            task=_tasks.InvokeFunction(is_policy_permissive_fn),
            result_path="$.policy_compliance",
            output_path="$.policy_compliance"
            )
 
        is_prev_policy_permissive_task = _sfn.Task(self, "isPrevPolicyPermissive",
            task=_tasks.InvokeFunction(is_policy_permissive_fn),
            result_path="$.policy_compliance",
            output_path="$.policy_compliance"
            )

        get_previous_bucket_policy_task = _sfn.Task(self, "getPreviousBucketPolicy",
            task=_tasks.InvokeFunction(get_previous_bucket_policy_fn),
            result_path="$"
            )

        restore_last_bucket_policy_task = _sfn.Task(self, "restoreLastPolicy",
            task=_tasks.InvokeFunction(put_policy_fn),
            result_path="$"
            )

        policy_remediation_failed = _sfn.Fail(self, "Policy Remediation Failed",
            cause="Policy Remediation Failed",
            error="Check Logs"
        )

        policy_compliant = _sfn.Succeed(self, "Policy Compliant",
            comment="Policy Compliance Evaluation Succeeded"
        )

        is_policy_remediation_complete = _sfn.Choice(self, "isPolicyRemediationComplete?")\
            .when(_sfn.Condition.boolean_equals("$.status", True), policy_compliant)\
            .when(_sfn.Condition.boolean_equals("$.status", False), policy_remediation_failed)\
            .otherwise(policy_remediation_failed)
        
        wait_x = _sfn.Wait(self, "Wait X Minutes - AWS Config Lags RealTime Configs",
            # duration=_sfn.WaitDuration.seconds_path("$.wait_time")
            time=_sfn.WaitTime.duration(core.Duration.minutes(4))
        )

        """
        remediate_weak_policy_sfn_definition = is_new_policy_permissive_task\
            .next(_sfn.Choice(self, "isPolicyAcceptable?")\
                # .when(_sfn.Condition.string_equals("$.status", "True"), "isJobComplete?")\
                .when(_sfn.Condition.boolean_equals("$.policy_status.is_compliant", True), policy_compliant)\
                .when(_sfn.Condition.boolean_equals("$.policy_status.is_compliant", False), get_previous_bucket_policy_task\
                        .next(is_prev_policy_permissive_task)\
                            .next(_sfn.Choice(self, "isPreviousPolicyAcceptable?")
                                .when(_sfn.Condition.boolean_equals("$.policy_status.is_compliant", False), policy_remediation_failed)\
                                .when(_sfn.Condition.boolean_equals("$.policy_status.is_compliant", True), restore_last_bucket_policy_task\
                                        .next(is_policy_remediation_complete) # State Function Choice
                                )
                                .otherwise(policy_remediation_failed)
                                )
                    )
                .otherwise(policy_remediation_failed)
                )
        """
        remediate_weak_policy_sfn_definition = is_new_policy_permissive_task\
            .next(_sfn.Choice(self, "isPolicyAcceptable?")\
                .when(_sfn.Condition.boolean_equals("$.policy_status.is_compliant", True), policy_compliant)\
                .when(_sfn.Condition.boolean_equals("$.policy_status.is_compliant", False), get_previous_bucket_policy_task\
                        .next(is_prev_policy_permissive_task)\
                            .next(_sfn.Choice(self, "isPreviousPolicyAcceptable?")
                                .when(_sfn.Condition.boolean_equals("$.policy_status.is_compliant", True), restore_last_bucket_policy_task\
                                        .next(is_policy_remediation_complete) # State Function Choice
                                )
                                .when(_sfn.Condition.boolean_equals("$.policy_status.is_compliant", False), policy_remediation_failed)\
                                .otherwise(policy_remediation_failed)
                                )
                    )
                .otherwise(policy_remediation_failed)
                )

        remediate_weak_policy_statemachine = _sfn.StateMachine(self, "stateMachineId",
                definition=remediate_weak_policy_sfn_definition,
                timeout=core.Duration.minutes(7)
            )
        core.Tag.add(remediate_weak_policy_statemachine,key="Owner",value=global_args.OWNER)
        core.Tag.add(remediate_weak_policy_statemachine, key="ToKnowMore",value=global_args.SOURCE_INFO)

        ###############################################################################
        ################# STEP FUNCTIONS EXPERIMENTAL CODE - UNSTABLE #################
        ###############################################################################

        put_policy_event_targets = []
        # put_policy_event_targets.append(_targets.LambdaFunction(handler=event_handler))
        put_policy_event_targets.append(
            _targets.SfnStateMachine( 
                machine=remediate_weak_policy_statemachine
            )
        )
        
        s3_put_policy_pattern = _events.EventPattern(
                source=["aws.s3"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": [
                    "s3.amazonaws.com"
                    ],
                    "eventName": [
                        "PutBucketPolicy"
                    ]
                }
            )

        put_s3_policy_event = _events.Rule(self,
            "puts3PolicyEventId",
            event_pattern = s3_put_policy_pattern,
            rule_name = f"put_s3_policy_event_{global_args.OWNER}",
            enabled = True,
            description = "Trigger an event for S3 PutBucketPolicy",
            targets = put_policy_event_targets
            )
        core.Tag.add(put_s3_policy_event,key="Owner",value=global_args.OWNER, include_resource_types=[])
        core.Tag.add(put_s3_policy_event, key="ToKnowMore",value=global_args.SOURCE_INFO)

        # Create s3 bucket
        pvt_bkt = _s3.Bucket(self, "s3bucket")
        core.Tag.add(pvt_bkt,key="isLeakBucket",value="True")
        core.Tag.add(pvt_bkt,key="Owner",value=global_args.OWNER)
        core.Tag.add(pvt_bkt, key="ToKnowMore",value=global_args.SOURCE_INFO)

        # create s3 notification for lambda function
        #  notification = aws_s3_notifications.LambdaDestination(is_policy_permissive_fn)

        # assign notification for the s3 event type (ex: OBJECT_CREATED)
        # pvt_bkt.add_event_notification(_s3.EventType.OBJECT_CREATED, notification)

        # Lets create a cloudtrail to track s3 data events
        s3_data_event_trail = _cloudtrail.Trail(
            self,
            "s3DataEventTrailId",
            is_multi_region_trail=False,
            include_global_service_events=False,
            enable_file_validation=True,
            send_to_cloud_watch_logs=True,
            cloud_watch_logs_retention=_logs.RetentionDays.ONE_WEEK
        )

        # Lets capture S3 Data Events only for our bucket- TO REDUCE COST
        s3_data_event_trail.add_s3_event_selector(
            prefixes=[
                f"{pvt_bkt.bucket_arn}/"
            ],
            include_management_events=True,
            read_write_type=_cloudtrail.ReadWriteType.WRITE_ONLY
        )

        ###########################################
        ################# OUTPUTS #################
        ###########################################

        output0 = core.CfnOutput(self,
            "SecuirtyAutomationFrom",
            value=f"{global_args.SOURCE_INFO}",
            description="To know more about this automation stack, check out our github page."
        )

        output1 = core.CfnOutput(self,
            "MonitoredS3Bucket",
            value=(
                    f"https://console.aws.amazon.com/s3/buckets/"
                    f"{pvt_bkt.bucket_name}"
                ),
            description=f"S3 Bucket to Update Policy"
        )
        output2 = core.CfnOutput(self,
            "CloudTrailForS3",
            value=(
                    # f"{s3_data_event_trail.trail_arn}"
                    f"https://console.aws.amazon.com/cloudtrail/home?region="
                    f"{core.Aws.REGION}#/configuration/"
                    f"arn:aws:cloudtrail:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:trail/"
                    f"{s3_data_event_trail.trail_arn}"
                ),
            description=f"This trail monitors our S3 Bucket for all PUT events"
        )
        output3 = core.CfnOutput(self,
            "S3PolicyValidatorStateMachine",
            value=(
                f"https://console.aws.amazon.com/states/home?"
                f"#/statemachines/view/"
                f"{remediate_weak_policy_statemachine.state_machine_arn}"
            ),
            description="The remediating state machine"
        )

        sampleWeakS3Policy={
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": f"133-PERMISSIVE-POLICY-{global_args.OWNER}",
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": [
                                        "s3:Get*"
                                    ],
                                    "Resource": f"{pvt_bkt.bucket_arn}"
                                }
                            ]
                        }
        
        sampleRestrictiveS3Policy={
                                    "Version":"2012-10-17",
                                    "Statement":[
                                        {
                                        "Sid": f"105-RESTRICTIVE-POLICY-{global_args.OWNER}",
                                        "Effect":"Allow",
                                        "Principal": {"AWS": [f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:root"]},
                                        "Action":["s3:PutObject"],
                                        "Resource":[f"{pvt_bkt.bucket_arn}/*"]
                                        }
                                    ]
                                }

        output4 = core.CfnOutput(self,
            "sampleWeakS3Policy",
            # value=(
            #     f'{{"Version":"2012-10-17","Statement":[{{"Sid":"PublicRead","Effect":"Allow","Principal":"*","Action":["s3:Get*"],"Resource":"{pvt_bkt.bucket_arn}"}}]}}'
            # ),
            value=json.dumps(sampleWeakS3Policy),
            description="WARNING:MAKES THE BUCKET PUBLIC READ."
        )

        output5 = core.CfnOutput(self,
            "sampleRestrictiveS3Policy",
            # value=(
            #     f'{{"Version":"2012-10-17","Statement":[{{"Sid":"PublicRead","Effect":"Allow","Principal":"*","Action":["s3:Get*"],"Resource":"{pvt_bkt.bucket_arn}"}}]}}'
            # ),
            value=json.dumps(sampleRestrictiveS3Policy),
            description="Allows the root user to Put Objects to this bucket."
        )
