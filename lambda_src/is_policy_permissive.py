#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
.. module: is_policy_permissive
    :Actions: Check if policy has wildcard ("*") permissions
    :platform: AWS
    :copyright: (c) 2020 Mystique.,
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Mystique
.. contactauthor:: miztiik@github issues
"""

import logging

__author__ = 'Mystique'
__email__ = 'miztiik@github'
__version__ = '0.0.1'
__status__ = 'production'


class global_args:
    """
    Helper to define global statics
    """
    OWNER = 'Mystique'
    ENVIRONMENT = 'production'
    REGION_NAME = 'us-east-1'
    TAG_NAME = 'put_policy'
    LOG_LEVEL = logging.INFO


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


def is_policy_permissive(policy):
    # Default we are ASSUMING the policy will be compliant
    policy_status = {'is_compliant': True}
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
                    policy_status = {'is_compliant': False,
                            'reason': 'Excessive permissive statement detected',
                            'statement': st
                            }
    return policy_status


def lambda_handler(event, context):
    logger.info(f'Event:{event}')
    resp = {'status': False, 'resource_id': '', 'is_prev_policy':False}
    EVENT_TYPE = 'PutBucketPolicy'
    n_policy= {}
    # Check if the event is triggered by CloudWatch Event
    if 'detail' in event and 'eventName' in event.get('detail'):
        if event.get('detail').get('eventName') == EVENT_TYPE:
            n_policy= event.get('detail').get('requestParameters'
                    ).get('bucketPolicy')
            resp['resource_id'] = event.get('detail'
                    ).get('requestParameters').get('bucketName')
    # Check if we are validating previous bucket policy - Triggered by State Machine
    # This will avoid infinite loop, if the previous policy is also bad and we go ahead with PutBucketPolicy
    # We are expecting two parameters in the event 'policy' and 'resource_id'
    if not n_policy and 'policy' in event:
        # Lets set the bucket name first
        resp['resource_id'] = event.get('resource_id')
        resp['is_prev_policy'] = True
        # Let us check if the previous policy is NULL (Buckets CAN have NO policy)
        if event.get('policy'):
            n_policy = event.get('policy')
        # If the previous policy is empty{}, make up compliance
        # Add all the dict keys manually
        if not event.get('policy'):
            resp['policy_status'] = {'is_compliant': True}
            resp['status'] = True
            resp['policy'] = event.get('policy')
            resp['message'] = 'Previous Policy is empty'
    # Finally lets evaluate if the policy is compliant
    if n_policy:
        resp['policy_status'] = is_policy_permissive(n_policy)
        # Add the statement back to status, if the policy is compliant
        if resp['policy_status']['is_compliant']:
            resp['policy'] = n_policy
        resp['status'] = True
    # TODO: What if no policy is send, how to handle it?
    return resp


if __name__ == '__main__':
    lambda_handler({}, {})
