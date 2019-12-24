# -*- coding: utf-8 -*-
"""
.. module: check_policy_strength
    :Actions: Check if policy has wildcard ("*") permissions
    :platform: AWS
    :copyright: (c) 2020 Mystique.,
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Mystique
.. contactauthor:: miztiik@github issues
"""

import boto3
import os
import json
from botocore.exceptions import ClientError
import logging

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
    logger.setLevel(global_args.LOG_LEVEL)
    # logging.basicConfig(format="[%(asctime)s] %(levelname)s [%(module)s.%(funcName)s:%(lineno)d] %(message)s", datefmt="%H:%M:%S"
    return logger

# Initialize Logger
logger = set_logging(logging.INFO)


def check_policy_strength(policy):
    # Default we are ASSUMING the policy will be compliant
    policy_status = { "is_compliant": True }

    for st in policy['Statement']:
      actions = st['Action']
    
      if isinstance(actions, str):
        actions = [actions]
    
      if st['Effect'] == 'Allow' and st['Principal'] == '*':
          for action in actions:
              parts = action.split(':')
              service = parts[0]
              call = parts[1]
              if call.startswith('Get') or call.startswith('Put'):
                  policy_status = { 
                      "is_compliant": False, 
                      "reason": "Excessive permissive statement detected", 
                      "statement": st 
                  }
    return policy_status


def lambda_handler(event, context):
    logger.info(f"Event:{event}")
    resp = {'status':False}
    EVENT_TYPE="PutBucketPolicy"
    if 'detail' in event and 'eventName' in event.get('detail'):
        if event.get('detail').get('eventName') == EVENT_TYPE:
            new_policy = event.get('detail').get('requestParameters').get('bucketPolicy')
            resp['resource_id'] = event.get('detail').get('requestParameters').get('bucketName')
            if new_policy:
                resp['policy_status'] = check_policy_strength(new_policy)
                resp['status'] = True
            else:
                resp['error_message'] = f"No bucket policy found"
    return resp

if __name__ == '__main__':
    lambda_handler({}, {})