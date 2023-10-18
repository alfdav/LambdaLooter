import os
import argparse
import subprocess
from subprocess import call
from concurrent.futures import ThreadPoolExecutor, wait
import boto3
from boto3 import Session
from time import gmtime, strftime
import time

import ec2looter
import parsing
import lambdalooter
import auth

PROG_NAME = "CLAWS - Credential Looter AWS"
PROG_VER = 0.01
PROG_DESC = "Download AWS code and scan for secrets."
PROG_EPILOG = "A.K.A Gimme Da Loot"
PROG_ORIGINS = "LambdaLooter at https://github.com/StateFarmIns/LambdaLooter"

def parse_args():
    """
    Parse cmd line args
    """
    parser = argparse.ArgumentParser(prog=PROG_NAME, description=PROG_DESC, epilog=PROG_EPILOG)
    parser.add_argument("--version", action="version", version="%(prog)s v"+str(PROG_VER))

    parser.add_argument("-p", "--profile", dest="profile", help="Single AWS profile you want scan for lambda code. Defaults to credentials file.")
    parser.add_argument("-r", "--region", dest="region", default="us-east-1", help="Your aws region you want to download lambda code from. Default=us-east-1.")
    parser.add_argument("-t", "--threads", dest="threads", default=10, type=int, help="Number of threads to download functions and scan for loot. Default=10.")
    parser.add_argument("-fv", "--versions", dest="versions", action='store_true', help="Download all versions of the Lambda code. Default=False.")
    parser.add_argument("-d", "--delete", dest="deldownloads", action='store_true', help="Delete the Zip files after you are done looting. Default=False.")
    parser.add_argument("-ro", "--role", dest="role", help="Role that you will use if trying to assume role chain.")
    parser.add_argument("-hu", "--hunt", dest="hunt", action='store_true', help="Hunt through all code in /loot. Default=False.")
    #Following variable set to lambduh because 'lambda' appears to be an object or something within python and I can't use it. Sadge.
    parser.add_argument("-l", "--lambda", dest="lambduh", action='store_true', help="Download Lambda code. Default=False.")
    parser.add_argument("-e", "--ec2", dest="ec2", action='store_true', help="Download EC2 users data. Default=False.")
    
    args = parser.parse_args()
    
    return args


def main(region, threads, deldownloads, getversions, hunt, ec2, lambduh, role, profile=None):       
    """
    Main function
    Sets the stage for everything!
    Variables - 
    region: aws region
    threads: number of threads for downloads
    deldownloads: YES or NO
    getversions: YES or NO
    profile: the AWS profile lambdas are downloaded from 
    """
    # Check/Creation of loot folder
    #_____________________________________________________________________________
    strLoot = os.path.isdir('./loot')
    if not strLoot:
        os.mkdir('loot')
        print("Created the folder:", 'loot')
    else:
        print('loot', "folder already exists.")
    #
    # If user does not supply a profile, we will grab profiles using boto3.session.Session().available_profiles which returns a list of our profiles we can attempt to auth to using our current creds.
    #______________________________________________________________________________
    if ec2 or lambduh:
        if profile is None:
            if threads == 1:
                for profileCurrent in boto3.session.Session().available_profiles:
                    awsProfileSetup(profileCurrent, region, threads, deldownloads, getversions, ec2, lambduh)
            else:    
                with ThreadPoolExecutor(threads) as executor:
                    #futures = [executor.submit(awsProfileSetup, profileCurrent, region, threads, deldownloads, getversions) for profileCurrent in profilelist]
                    futures = [executor.submit(awsProfileSetup, profileCurrent, region, threads, deldownloads, getversions, ec2, lambduh) for profileCurrent in boto3.session.Session().available_profiles]
                    #wait for all tasks to complete
                    wait(futures)
        #   
        # If a profile was given, this will run. 
        #_______________________________________________________________________________    
        if profile is not None:
            awsProfileSetup(profile, region, threads, deldownloads, getversions, ec2, lambduh)
    #
    # if hunt flag was included, this will run. 
    #_______________________________________________________________________________  
    #print(threads)
    if hunt:
        if profile is None:
            if threads == 1:
                for profileCurrent in boto3.session.Session().available_profiles:
                    parsing.hunt(threads, deldownloads, getversions, profileCurrent)
            else:    
                with ThreadPoolExecutor(threads) as executor:
                    #futures = [executor.submit(awsProfileSetup, profileCurrent, region, threads, deldownloads, getversions) for profileCurrent in profilelist]
                    futures = [executor.submit(parsing.hunt, threads, deldownloads, getversions, profileCurrent) for profileCurrent in boto3.session.Session().available_profiles]
                    #wait for all tasks to complete
                    wait(futures)
        if profile is not None:
            parsing.hunt(threads, deldownloads, getversions, profile)
            
    print("Thanks for looting with us!")
    

def awsProfileSetup(profile, region, threads, deldownloads, getversions, ec2, lambduh):
    """
    AWS functions to interact with AWS profiles.
    Either from a file list or single specified profile
    Variables - 
    profile: the AWS profile to interact with
    region: aws region
    threads: number of threads for downloads
    deldownloads: YES or NO
    getversions: YES or NO
    ec2: YES or NO
    lambduh: YES or NO
    hunt YES or NO
    """
    
    #
    # Check to see if you have current valid creds, or if you need to get/refresh them. 
    #______________________________________________________________________________

    failed = False
    boto3.setup_default_session(profile_name=profile)
    try: 
        sts_client = boto3.client('sts')
        sts_client.get_caller_identity()
    except:
        print("Not Authed")
        authID.example(profileID, region)
        try:
            sts_client = boto3.client('sts')
            sts_client.get_caller_identity()
        except:
            failed = True
    #
    # Creating the file for our profile findings and files. 
    #______________________________________________________________________________
    if not failed:
        os.environ["AWS_PROFILE"] = profile
        print("Creating directory to store functions")
        strExists = os.path.isdir('./loot/' + profile)
        if not strExists:
            os.mkdir('./loot/' + profile)
            print("Created the folder:", profile)
        else:
            print(profile, "folder already exists....moving on.")
        
        #
        # Initial flow of downloading. One at a time in order
        #______________________________________________________________________________
        #
        # If ec2 flag was given, then we will create an ec2_client object and call ec2looter
        if ec2:
            boto3.setup_default_session(profile_name=profile)
            ec2_client = boto3.client('ec2', region_name=region)
            ec2looter.loot(profile, ec2_client, deldownloads)
        #
        # If lambda flag was given, then we will create an lambda_client object and call lambdalooter 
        if lambduh:
            boto3.setup_default_session(profile_name=profile)
            lambda_client = boto3.client('lambda', region_name=region)
            lambdalooter.loot(profile, lambda_client, threads, getversions, deldownloads)
    

if __name__ == "__main__":
    args = parse_args()
    
    main(args.region, args.threads, args.deldownloads, args.versions, args.hunt, args.ec2, args.lambduh, args.role, profile=args.profile)