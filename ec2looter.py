import boto3
from boto3.session import Session
import os
import base64
import pathlib
import zipfile
from pprint import pprint
from datetime import datetime
from dateutil import tz


def loot(profile, ec2_client, deldownloads, jsonTracker):       
    """
    Main function
    ec2_client: Object for the ec2_client call
    profile: the AWS profile lambdas are downloaded from
    deldownloads: boolean in case you want to delete the downloaded files
    """
    downloadEC2Users(profile, ec2_client, deldownloads, jsonTracker)


def downloadEC2Users(profile, ec2_client, deldownloads, jsonTracker):
    try:
        response = ec2_client.describe_instances()
    except Exception as e:
        with open(f'./logs/failures.log', "a") as code:
            code.write(f"Failed, {profile}, " + str(e) + "\n")
        return 1 
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            try:
                response = ec2_client.describe_instance_attribute(
                    Attribute= "userData",
                    DryRun=False,
                    InstanceId=instance["InstanceId"]
                )
            except Exception as e:
                with open(f'./logs/failures.log', "a") as code:
                    code.write(f"Failed, {profile}, " + str(e) + "\n")
                continue
            lastChecked = datetime.strptime(jsonTracker['ec2LastChecked'],'%Y-%m-%d %H:%M:%S.%f%z')
            to_zone = tz.tzutc()
            lastChecked = lastChecked.replace(tzinfo=to_zone)
            startupTime = instance['LaunchTime']
            startupTime = startupTime.replace(tzinfo=to_zone)
            if lastChecked < startupTime:
                if response['UserData'].get('Value') == None:
                    continue
                sample = base64.b64decode(response['UserData']['Value'])
                try:
                    decodedsample = sample.decode("ascii")
                except UnicodeDecodeError:
                    try:
                        decodedsample = sample.decode("utf-8")
                    except UnicodeDecodeError as e:
                        with open(f'./logs/failures.log', "a") as code:
                            code.write(f"Failed, {profile}, " + str(e) + "\n")
                        continue
                saveEC2FilePath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "/ec2/ec2_" + instance["InstanceId"] + "-ec2-UsersFile.txt")
            
                with open(saveEC2FilePath, 'w') as outputfile:
                    outputfile.write(decodedsample)
                
    zipEC2File(profile, deldownloads)



def zipEC2File(profile, deldownloads):
    zipDirectory = pathlib.Path("./loot/" + profile + "/ec2")
    zipDirectory.mkdir(exist_ok=True)
    filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "/" + "ec2Users.zip")
    counter = 0
    with zipfile.ZipFile(filepath , mode="w") as archive:
        for file_path in zipDirectory.iterdir():
            archive.write(file_path, arcname=file_path.name)
            counter += 1
            if deldownloads:
                os.remove(file_path)
    print(f'Number of EC2 Files Zipped: {counter}')
