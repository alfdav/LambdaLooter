import boto3
from boto3.session import Session
import os
import base64
import pathlib
import zipfile


def loot(profile, ec2_client, deldownloads):       
    """
    Main function
    ec2_client: Object for the ec2_client call
    profile: the AWS profile lambdas are downloaded from
    deldownloads: boolean in case you want to delete the downloaded files
    """
    print("ec2loot.py()")
    downloadEC2Users(profile, ec2_client, deldownloads)


def downloadEC2Users(profile, ec2_client, deldownloads):
    response = ec2_client.describe_instances()
    #print(response)
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            # This sample print will output entire Dictionary object
            #print(instance)
            # This will print will output the value of the Dictionary key 'InstanceId'
            #print(instance[ "InstanceId"])
            response = ec2_client.describe_instance_attribute(
                Attribute= "userData",
                DryRun=False,
                InstanceId=instance["InstanceId"]
            )
            #print(response['UserData']['Value'].decode(ascii))
            sample = base64.b64decode(response['UserData']['Value'])
            #print(base64.b64decode(response['UserData']['Value']))
            #print(sample)
            decodedsample = sample.decode("ascii")
            #print(decodedsample)
            
            strLoot = os.path.isdir("./loot/" + profile + "/ec2")
            if not strLoot:
                os.mkdir("./loot/" + profile + "/ec2")
            
            saveEC2FilePath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "/ec2/" + instance["InstanceId"] + "-ec2-UsersFile.txt")
            
            with open(saveEC2FilePath, 'w') as outputfile:
                outputfile.write(decodedsample)
                
    zipEC2File(profile, deldownloads)



def zipEC2File(profile, deldownloads):
    zipDirectory = pathlib.Path("./loot/" + profile + "/ec2")
    zipDirectory.mkdir(exist_ok=True)
    filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "/" + "ec2Users.zip")
    print("Writing ZIP file to scan for loot!")
    print(filepath)
    with zipfile.ZipFile(filepath , mode="w") as archive:
        for file_path in zipDirectory.iterdir():
            archive.write(file_path, arcname=file_path.name)
            if deldownloads:
                os.remove(file_path