import os
import json
import subprocess
import zipfile
import pathlib
from zipfile import ZipFile
from concurrent.futures import ThreadPoolExecutor, wait
import shutil
import boto3
import requests


def loot(profile, lambda_client, threads, getversions, deldownloads):       
    """
    Variables - 
    lambda_client: lambda client object for downloading. 
    threads: number of threads for downloads
    deldownloads: YES or NO
    getversions: YES or NO
    profile: the AWS profile lambdas are downloaded from 
    """
    downloadLambdas(profile, lambda_client, threads, getversions, deldownloads)


def deleteDownload(profile):
    """
    Delete the downloaded zip
    Variables - 
    profile: name of profile to match to directory name for deleting
    """
    try:
    
        filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/{}".format(profile))
        shutil.rmtree(filepath, ignore_errors=True)
    
    except Exception as e:
        print("Error: {0} : {1}".format(filepath, e.strerror))


def downloadLambdas(profile, lambda_client, threads, getversions, deldownloads):
    """
    Thread download lambda 'checkVersions' function
    Variables - 
    profile: the AWS profile lambdas are downloaded from
    lambda_client: lambda client object for downloading. 
    threads: number of threads for downloads
    getversions: YES or NO
    deldownloads: Should we delete data after we are done?
    """

    func_paginator = lambda_client.get_paginator('list_functions')
    for func_page in func_paginator.paginate():
    
        with ThreadPoolExecutor(threads) as executor:
                
            futures = [executor.submit(checkVersions, profile, func['FunctionArn'], lambda_client, getversions) for func in func_page['Functions']]
            #wait for all tasks to complete
            wait(futures)

    
    zipEnvironmentVariableFiles(profile, deldownloads)

def zipEnvironmentVariableFiles(profile, deldownloads):

    zipDirectory = pathlib.Path("./loot/" + profile + "/env")
    zipDirectory.mkdir(exist_ok=True)
    filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "/" + "envVariables.zip")
    print("Writing ZIP file to scan for loot!")
    with zipfile.ZipFile(filepath , mode="w") as archive:
        for file_path in zipDirectory.iterdir():
            archive.write(file_path, arcname=file_path.name)
            if deldownloads:
                os.remove(file_path)
    
def downloadExecution(profile, strFunction, lambda_client):
    """
    execute the download of the lambdas function(s) and Envionrment Varilables
    Variables - 
    profile: the AWS Profile we are looting
    lambda_client: lambda client object for downloading. 
    strFunction: arn of the lambda to download
    profile: the AWS profile lambdas are downloaded from
    """


    func_details = lambda_client.get_function(FunctionName=strFunction)
    downloadDir = "./loot/" + profile + "/" + func_details['Configuration']['FunctionName']  + "-version-" + func_details['Configuration']['Version'] + ".zip" 
    print("Downloading code for: " + profile + ":" + func_details['Configuration']['FunctionName'] + " Version: " + func_details['Configuration']['Version'])

    url = func_details['Code']['Location']
    
    r = requests.get(url)
    with open(downloadDir, "wb") as code:
        code.write(r.content)

    print("Checking Environment Variables for " +profile +":" + func_details['Configuration']['FunctionName']  + " Version: " + func_details['Configuration']['Version'])

    strLoot = os.path.isdir("./loot/" + profile + "/env")
    if not strLoot:
        os.mkdir("./loot/" + profile + "/env")

    saveEnvFilePath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "/env/" + func_details['Configuration']['FunctionName'] + "-"  + func_details['Configuration']['Version'] + "-environmentVariables-loot.txt")

    env_details = lambda_client.get_function_configuration(FunctionName=strFunction)    
    details = env_details['Environment']['Variables']

    with open(saveEnvFilePath, 'a') as outputfile:
        outputfile.write("----------------------------\n")
        outputfile.write("ENVVAR: {}\n".format(details))
        outputfile.write("----------------------------\n")
        outputfile.write("\n")

def checkVersions(profile, strFunction, lambda_client, getversions):
    """
    check if we are downloading all versions of the lambdas function calls downloadExecution
    If we are downloading multiple versions paginate
    Variables - 
    profile: the AWS Profile we are looting
    strFunction: arn of the lambda to download
    lambda_client: lambda client object for downloading. 
    getversions: YES or NO
    """

    #lambda_client = boto3.client('lambda',region_name=region)

    if getversions:
        
        func_paginator = lambda_client.get_paginator('list_versions_by_function')
        
        for func_page in func_paginator.paginate(FunctionName=strFunction):
            for func in func_page['Versions']:
                strFunction = func['FunctionArn']
                downloadExecution(profile, strFunction, lambda_client)
    else:
        downloadExecution(profile, strFunction, lambda_client)