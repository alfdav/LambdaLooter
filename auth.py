import boto3
from boto3.session import Session
import os
import subprocess
from pprint import pprint
import time
import datetime
from time import gmtime, strftime


def authID(profileID, region):
    # 
    # Auth is the trikciest part. I recommend if you need to actively grab new credentials from accounts on the go, 
    # This may or may not work for you. Authing is something that is generally specific per organization as there are many different tools/federation options to help facilitate authentication to cloud resources. 
    # The below code will take in an account ID's and assume a role that was passed in. 
    # The requires the creds you are using to be able to assume role to another account.
    # Other methods may include if you have a prefered way internally in your company to call something to get new creds, code that into this authExample() and simply call authExample() or whatever you rename it, to auth with whateveer your internal auth method is.
    #__________________________________________________________________________________________
    os.environ["AWS_REGION"] = region 
    boto3.setup_default_session(profile_name=profile)
    current_identity = boto3.client('sts').get_caller_identity()
    pprint(current_identity)

    target_role_name = role
    role_session_name = current_identity['Arn'].split("/")[-1]

    sts_client = boto3.client('sts')
    print(sts_client)

    assume_role_arn = f"arn:aws:iam::{profile}:role/{target_role_name}"
    aro = sts_client.assume_role(RoleArn=assume_role_arn, RoleSessionName=role_session_name)

    ar_session = Session(aws_access_key_id = aro['Credentials']['AccessKeyId'],
                                 aws_secret_access_key = aro['Credentials']['SecretAccessKey'],
                                 aws_session_token = aro['Credentials']['SessionToken'])

    current_identity = ar_session.client('sts').get_caller_identity()
    pprint(current_identity)
    
    
def authExample(profile, region):
    #The following code is example code of a loop that will attempt to auth 5 times and if it fails all 5, it will write an error to an error file. 
    test = os.system("c:Path\\to\\auth\\exe login aws" + profile)
    loopmax=0
    #print(test)
    while test != 0 and loopmax < 5: #This is just a check to see if the loop max is hit or if the test gave an error
        #print(test)
        loopmax += 1
        #print(loopmax)
        test = os.system("c:Path\\to\\auth\\exe login aws" + profile)
        #print("repeat try")
        time.sleep(1)
        if loopmax == 5 and test != 0:
            profileFindings = os.path.isdir('./loot/error/')
            if not profileFindings:
                #print("Make directory")
                os.mkdir('./loot/error/')
            filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "./loot/error/error.txt")
            errorfile = os.path.isfile(filepath)
            print(errorfile)
            if not errorfile:
                with open(filepath, 'w') as lf:
                    pass
            print(filepath)
            with open(filepath, 'a') as outputfile:
                outputfile.write(strftime("%Y-%m-%d %H:%M:%S", gmtime()) + ": error: cannot auth to " + profile)
                outputfile.write("\n")