import boto3
import os
import json
from pprint import pprint
from dateutil import tz
import pathlib
import zipfile
from datetime import datetime

def main():

    boto3.setup_default_session(region_name='us-east-1')
    ssm_client = boto3.client('ssm')
    deldownloads = False
    profile = 'profile for individual runs'
    jsonTracker = {'LambdaLastChecked' : '1999-12-04 18:40:54.529028+00:00',
                   'ec2LastChecked' : '1999-12-04 18:40:54.529028+00:00',
                   'ssmLastChecked': '2020-12-04 18:40:54.529028+00:00'}

    loot(profile, ssm_client, deldownloads, jsonTracker)

# CreatedDate within the document information is actually the last edited date. It is updated everytime you edit and save the preferences. We will check to make sure that we only download new SSM profiles since the last run based on this field. 
def loot(profile, ssmclient, deldownloads, jsonTracker):
    counter = 0
    
    try:
        paginator = ssmclient.get_paginator('list_documents')
        for page in paginator.paginate():
            continue
    except Exception as e:
        with open(f'./logs/failures.log', "a") as code:
            code.write(f"Failed, {profile}, " + str(e) + "\n")
        return 1


    for page in paginator.paginate():
        for document in page['DocumentIdentifiers']:
            ssmpref = ssmclient.get_document(Name=document['Name'])
            created = ssmpref['CreatedDate']
            lastChecked = datetime.strptime(jsonTracker['ssmLastChecked'],'%Y-%m-%d %H:%M:%S.%f%z')
            to_zone = tz.tzutc()
            lastChecked = lastChecked.replace(tzinfo=to_zone)
            if lastChecked < created:
                if document['Owner'] != "Amazon":
                    saveFilePath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "/ssm/ssm_" + document['Name'] + "-ssm-documents.txt")
                    counter += 1
                    with open(saveFilePath, 'w') as outputfile:
                        outputfile.write(ssmpref['Content'])
    
    print(f'ssm preferences seen: {counter}')


    zipSSMFile(profile, deldownloads)


def zipSSMFile(profile, deldownloads):
    zipDirectory = pathlib.Path("./loot/" + profile + "/ssm")
    zipDirectory.mkdir(exist_ok=True)
    filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "/" + "ssm-documents.zip")
    counter = 0
    with zipfile.ZipFile(filepath , mode="w") as archive:
        for file_path in zipDirectory.iterdir():
            archive.write(file_path, arcname=file_path.name)
            counter += 1
            if deldownloads:
                os.remove(file_path)
    print(f'SSM preference files zipped: {counter}')

if __name__ == "__main__":
    main()
