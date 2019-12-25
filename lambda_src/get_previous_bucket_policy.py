# -*- coding: utf-8 -*-
"""
.. module: get_previous_bucket_policy
    :Actions: get_previous_bucket_policy for given resource
    :platform: AWS
    :copyright: (c) 2020 Mystique.,
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Mystique
.. contactauthor:: miztiik@github issues
"""

import json
import logging

import boto3
from botocore.exceptions import ClientError

__author__      = 'Mystique'
__email__       = 'miztiik@github'
__version__     = '0.0.1'
__status__      = 'production'

"""
GENERIC HELPERS
"""

class global_args:
    """
    Helper to define global statics
    """
    OWNER                       = 'Mystique'
    ENVIRONMENT                 = 'production'
    REGION_NAME                 = 'us-east-1'
    TAG_NAME                    = 'put_policy'
    LOG_LEVEL                   = logging.INFO


def set_logging(lv=global_args.LOG_LEVEL):
    '''
    Helper to enable debugging
    '''
    logging.basicConfig(level=lv)
    logger = logging.getLogger()
    logger.setLevel(lv)
    # logging.basicConfig(format="[%(asctime)s] %(levelname)s [%(module)s.%(funcName)s:%(lineno)d] %(message)s", datefmt="%H:%M:%S"
    return logger

# Initialize Logger
logger = set_logging(logging.INFO)


def lambda_handler(event, context):
    resp = {'status': False, 'policy':{}}
    logger.info(f"Event:{event}")
    client = boto3.client('config')
    try:
        response = client.get_resource_config_history(
            resourceType='AWS::S3::Bucket',
            resourceId=event['resource_id'],
            # resourceId=event.get('id')
            limit=1
        )
        last_config = response['configurationItems'][0]
        policy_obj = json.loads(last_config['supplementaryConfiguration']['BucketPolicy'])

        # Buckets can have empty policy - so previous policy can be NONE
        if policy_obj['policyText']:
            resp['policy'] = json.loads(policy_obj['policyText'])
        resp['resource_id'] = event['resource_id']
        resp['status'] = True
    except ClientError as e:
        logger.error("Unable to get previous bucket policy")
        logger.error(f"ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp


if __name__ == '__main__':
    lambda_handler({}, {})
