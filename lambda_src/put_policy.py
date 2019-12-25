# -*- coding: utf-8 -*-
"""
.. module: put_policy
    :Actions: PUTS the given policy for the given resource
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


def put_policy(bucket, policy):
    resp = {'status': False}

    client = boto3.client('s3')
    try:
        # At times buckets have null - {} policy
        if policy:
            resp['message'] = client.put_bucket_policy(
                Bucket=bucket,
                Policy=json.dumps(policy)
            )
        else:
            resp['message'] = client.delete_bucket_policy(
                Bucket=bucket
            )
        resp['status'] = True
    except ClientError as e:
        logger.error("Unable to put bucket policy")
        logger.error(f"ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp


def lambda_handler(event, context):
    resp = {'status': False}
    bucket_name = event.get('resource_id')
    policy = event.get('policy')
    resp = event
    if bucket_name and policy is not None:
        resp['response'] = put_policy(bucket_name, policy)
        # Mov status from response to parent dict - silently
        resp['status'] = resp['response'].pop('status', None)
    return resp


if __name__ == '__main__':
    lambda_handler({}, {})
