import boto3
from boto3.session import Session
import os
import subprocess
from pprint import pprint
import time
import datetime
from time import gmtime, strftime


def getDefault():
    boto3.setup_default_session()
    current_identity = boto3.client('sts').get_caller_identity()
    sts_client = boto3.client('sts')
    return sts_client

def authID(profileID, region, role, sts_client):
    base_identity = boto3.client('sts').get_caller_identity()
    
    # This checks to see if the profile we want to look at is the profile we already ahve access to
    # If so, we do NOT want to assume role chain and we want to simply utilize our default session 
    if profileID == base_identity['Account']:
        clients = {
                'ec2client': boto3.client('ec2',region_name=region),
                'lambdaclient' : boto3.client('lambda',region_name=region),
                'ssmclient' : boto3.client('ssm',region_name=region)} 
    
    else:
        assume_role_arn = f"arn:aws:iam::{profileID}:role/{role}"
        aro = sts_client.assume_role(RoleArn=assume_role_arn, RoleSessionName=role)
        ar_session = Session(
                aws_access_key_id = aro['Credentials']['AccessKeyId'],
                aws_secret_access_key = aro['Credentials']['SecretAccessKey'],
                aws_session_token = aro['Credentials']['SessionToken'],
                region_name = region
                )
        current_identity = ar_session.client('sts').get_caller_identity()
        clients = {
                'ec2client': ar_session.client('ec2'),
                'lambdaclient' : ar_session.client('lambda'),
                'ssmclient' : ar_session.client('ssm')}
    return clients
   
