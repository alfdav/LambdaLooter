import os
import json
import argparse
import zipfile
import pathlib
from zipfile import ZipFile
import re
import glob
import importlib
import importlib.util
import subprocess
from subprocess import call
from concurrent.futures import ThreadPoolExecutor, wait
import shutil
import gc
import boto3
from boto3 import Session
import requests

from constants import FILE_TYPES



def hunt(threads, deldownloads, getversions, profile=None):       
    """
    Main function
    Sets the stage for everything!
    Variables - 
    threads: number of threads for downloads
    deldownloads: YES or NO
    getversions: YES or NO
    profile: the AWS profile lambdas are downloaded from 
    """
    

    strLoot = os.path.isdir('./loot')
    if not strLoot:
        os.mkdir('loot')
        print("Created the folder:", 'loot')
            
    else:
        print('loot', "folder already exists.")
    
    sigs = getSigs()
        
    
    if profile is None:
        # if user doesn't supply a profile, we will grab every file within /loot and search through it.
        rootdir = '.\loot'
        for file in glob.glob(rootdir + r'\*', recursive=False):
            #print(file)
            threadSecrets(threads, deldownloads, file.split('\\')[-1], sigs)
            '''with ThreadPoolExecutor(threads) as executor:
            futures = [executor.submit(threadSecrets, threads, deldownloads, file.split('\\')[-1], sigs) for file in glob.glob(rootdir + r'\*', recursive=False)]
            #wait for all tasks to complete
            wait(futures)'''
            
    if profile is not None:
        # user supplied single aws profile, lets roll
        threadSecrets(threads, deldownloads, profile, sigs)

def getSigs():
    #
    # This will create an array of json signature objects to iterate through based on the files starting with sig_
    # In future we can add a flag to ask for the file or naming scheme of the file and have the signatures loaded that way. 
    #______________________________________________________________________________
    sigs = []
    sigfiles = os.listdir(os.path.join(os.path.dirname(os.path.realpath(__file__)), "signatures"))
    for sigfile in sigfiles:
        try:
            if sigfile.startswith('sig_'):
                #pull in all sig files from the signature dir
                #prepare the module name so we can dynamically import it
                #dynamically import the sig file so we can use the Sig dict inside
                sigfilePath =  os.path.join(os.path.dirname(os.path.realpath(__file__)), "signatures/" + sigfile)
                jsonSigs = json.load(open(sigfilePath))
                for sigType in jsonSigs[0]["sigs"]:
                    sigs.append(sigType)
        except Exception as e:
            print("Something happened and the world is probably going to end " + str(e))
    #for sig in sigs:
        #print(sig)
        
    return(sigs)
 
def threadSecrets(threads, deldownloads, profile, sigs):
    """
    Thread the checkSecrets function
    Variables - 
    threads: number of threads for downloads
    deldownloads: YES or NO
    profile: the AWS profile to interact with
    """
    
    print("Scanning for Secrets in " + profile)
    rootdir = './loot'
    files = glob.glob(rootdir + r'/' + profile + '/*.zip', recursive=True)



    for f in files:
        checkSecrets(f, deldownloads, profile, sigs)

    '''with ThreadPoolExecutor(threads) as executor:
            
        futures = [executor.submit(checkSecrets, f, deldownloads, profile) for f in files]
        #wait for all tasks to complete
        wait(futures)'''

    if deldownloads:
        deleteDownload(profile)

def regexChecker(pattern, fileread):
    #print('regexChecker()')
    returnvalue = re.finditer(b"%b" % pattern.encode(), fileread, re.MULTILINE | re.IGNORECASE)
    #print(returnvalue)
    #print("we tried")
    return returnvalue
    #return re.finditer(b"%b" % pattern.encode(), fileread, re.MULTILINE | re.IGNORECASE)
                                                    
    

def checkSecrets(f,deldownloads, profile, sigs):
    """
    Search through lambda zip for secrets based on signatures
    Variables - 
    f: zip file to search through
    """
    #print("checkSecrets()")
    
    
    #print(files) # as list
    #print(f) # nice looking single line per file
    try:
        with ZipFile(f, "r") as inzip:
            for name in inzip.namelist():
                #print(name)
                if pathlib.Path(name).suffix in FILE_TYPES:
                    #print(name)
                    with inzip.open(name) as zipfile:
                        a = zipfile.read()
                        #print("zipfile.read")
                        for sigType in sigs:
                            #regex patterns portion
                            #This does not care about the file name, simply the type field set to regex. 
                            #print("loaded that sig")
                            #print(sigType['type'])
                            #print(sigType['pattern'])
                            if sigType['type'] == 'regex':
                                #print(f)
                                #print(name)
                                #print(sigType['pattern'])
                                for outp in regexChecker(sigType['pattern'], a):
                                    #print(outp)
                                    start = outp.span()[0]
                                    line_no = a[:start].count(b"\n") + 1
                                    try:
                                        output = str(outp.group(), 'UTF-8')
                                    except:
                                        print("Way too ugly...moving on") 
                                    findingChecker(profile, {
                                        'zip': f, 
                                        'lamda': name,
                                        'description': sigType['caption'],
                                        'output': output,
                                        'line_no': line_no,
                                        'fileread': a,
                                        'pattern': sigType['pattern']
                                        })

                            #string Match portion. 
                            elif sigType['type'] == 'match':
                                mrPat = sigType['pattern'].encode()
                                if mrPat in a:
                                    for m in re.finditer(mrPat, a):
                                        start = m.start()
                                        line_no = a[:start].count(b"\n") + 1
                                        start_of_line = a[:start].rfind(b"\n") + 1
                                        end_of_line = a[start:].find(b"\n")
                                        fullLine = a[start_of_line:end_of_line+start]
                                        prettyPrintThatOutput(profile, { 
                                            'zip': f, 
                                            'lamda': name,
                                            #'description': 'Found pattern match: {}'. format(sigType['pattern']),
                                            'description': sigType['caption'],
                                            'output': fullLine,
                                            'line_no': line_no,
                                            'fileread': a
                                            })
                                        
                            else:
                                continue                         
                        del a
                        gc.collect()    
    except Exception as e:
        print("That zip file was wack! " + str(e))

    if deldownloads:
        os.remove(f)

def keyCertChecker(profile, output: dict):
    print("keyCertChecker")
    usernameRegex = ["""['"][uU][sS][eE][rR]_?([nN][aA][mM][eE])?['"]{1} ?[:=] ?['"]([A-Za-z0-9_-])+['"]{1}"""]
    hostnameRegex = ["""['"][hH][oO][sS][tT]_?([nN][aA][mM][eE])?(['"]){1} ?[:=] ?['"]([A-Za-z0-9.-])+(['"]){1}"""]
    print(output['output'])
    newOutputUser = []
    for regex in usernameRegex:
        #print(regex)
        for outp in regexChecker(regex, output['fileread']):
            #print("For outp")
            try:
                outputUser = (str(outp.group(), 'UTF-8'))
                #print(outputUser)
                newOutputUser.append(outputUser)
            except:
                print("Way too ugly...moving on")
                
    newOutputUser = set(newOutputUser)
    print("newOutputUser: " + str(newOutputUser))
    newOutputHost = []
    for regexH in hostnameRegex:
        #print(regex)
        for outHost in regexChecker(regexH, output['fileread']):
            #print("For outp")
            try:
                outputHost = (str(outHost.group(), 'UTF-8'))
                #print(outputUser)
                newOutputHost.append(outputHost)
            except:
                print("Way too ugly...moving on")
    newOutputHost = set(newOutputHost)
    print("newOutputHost: " + str(newOutputHost))
    output.update({"PossibleHosts": str(newOutputHost),
                    "PossibleUsers": str(newOutputUser)
    })            
    prettyPrintThatOutput(profile, output)   

def awsKeyChecker(profile, output: dict):
    #print("awsKeyChecker()")
    accessKeyRegex = ["""['"]([a-zA-Z0-9+/]{40})['"]"""]
    newOutputAccess = []
    sessionTokenRegex = ["""['"]?[sS][eE][sS][sS][iI][oO][nN][_-]?([tT][oO][kK][eE][nN])?['"]{1} ?[:=] ?['"]?([A-Za-z0-9_\/+])+['"]{1}"""]
    newSessionToken = []
    quoteremoval = ['"', "'"]
    key = output['output']
    #print(key)
    for each in quoteremoval:
        key = key.replace(each,"")
    #print(key)
    output.update({'output': key})

    boto3.setup_default_session(profile_name=profile)
    sts_client = boto3.client('sts')

    try:
        response = sts_client.get_access_key_info(
            AccessKeyId=key
        )
        #print(response['Account'])
        for keyRegex in accessKeyRegex:
            for outAccess in regexChecker(keyRegex, output['fileread']):
                #print("For outp")
                try:
                    outputAccess = (str(outAccess.group(), 'UTF-8'))
                    #print(outputUser)
                    newOutputAccess.append(outputAccess)
                except:
                    print("Way too ugly...moving on")
        newOutputAccess = set(newOutputAccess)
        for sessionRegex in sessionTokenRegex:
            for outSession in regexChecker(sessionRegex, output['fileread']):
                #print("For outp")
                try:
                    outputSessionToken = (str(outSession.group(), 'UTF-8'))
                    #print(outputUser)
                    
                    newSessionToken.append(outputSessionToken)
                except:
                    print("Way too ugly...moving on")
        newSessionToken = set(newSessionToken)
        output.update({"PossibleAccessKeys": newOutputAccess,
                        "PossibleSessionTokens": newSessionToken,
                        "AccountID": response1['Account']
                        })
        prettyPrintThatOutput(profile, output)
    except: 
        print("Not Valid")
    
    
 
def findingChecker(profile, output: dict):
    """
    This will check every finding to see if there is anything else around it. 
    Variables -
    profile: the AWS profile lambdas are downloaded from 
    output: Found secrets from given signature
    
    """
    #print(output)
    #print('findingChecker()')
    
    #paircheckers are the regex that match pem/rsa key pairs which might have an endpoint or username connected to them or near them. 
    pairCheckers = ["REGEX KEY","REGEX CERTIFICATE"]
    awsKeys = ["REGEX Potential AWS Token"]
    #print(pairCheckers)
    #print(output['lamda'])
    #print(output['description'])
    #print(output['output'])
    fileexclusions = []
    excluded = False
    for file in fileexclusions:
        #print(file + " ?=? " + output['lamda'])
        if file in output['lamda']:
            excluded = True
            #print("True")
            
            
    
    if excluded == True:
        print(output['lamda'] + " excluded in " + profile)
    elif output['description'] in pairCheckers:
        keyCertChecker(profile, output)
    elif output['description'] in awsKeys:
        awsKeyChecker(profile, output)

    else:
        prettyPrintThatOutput(profile, output)
    
    
    
def prettyPrintThatOutput(profile, output: dict):
    """
    Pretty print found secretes to console and file
    Variables -
    profile: the AWS profile lambdas are downloaded from 
    output: Found secrets from given signature
    """
    #print("prettyPrintThatOutput()")
    profileFindings = os.path.isdir('./loot/findings/')
    #print(profileFindings)
    #print(output)
    if not profileFindings:
        #print("Make directory")
        os.mkdir('./loot/findings/')
    #print("Checking if loot/findings exists")
    if "PROD" in output['zip'].toUpper() or "PRODUCTION" in output['zip'].toUpper():
        profileFindings = os.path.isdir('./loot/findings/prod/')
        #print(profileFindings)
        #print(output)
        if not profileFindings:
            #print("Make directory")
            os.mkdir('./loot/findings/prod')
        filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/findings/prod/{}.txt".format(os.path.basename(output['description'])))
    elif "TEST" in output['zip'].toUpper():
        profileFindings = os.path.isdir('./loot/findings/test/')
        #print(profileFindings)
        #print(output)
        if not profileFindings:
            #print("Make directory")
            os.mkdir('./loot/findings/test')
        filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/findings/test/{}.txt".format(os.path.basename(output['description'])))
    elif "RSCH" in output['zip'].toUpper() or "RESEARCH" in output['zip'].toUpper():
        profileFindings = os.path.isdir('./loot/findings/rsch/')
        #print(profileFindings)
        #print(output)
        if not profileFindings:
            #print("Make directory")
            os.mkdir('./loot/findings/rsch')
        filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/findings/rsch/{}.txt".format(os.path.basename(output['description'])))
    
    print("profile: " + profile + " ZIP File: " + output['zip'] + " Lambda: " + output['lamda'])
    #print(filepath)
    #print("-*-*- This sig matched {0}. Check file for findings in './loot/" + profile + "/findings/'" )
    strLootFile = os.path.isfile(filepath)
    #print(strLootFile)
    if not strLootFile:
        with open(filepath, 'w') as lf:
            pass
    #print("output")
    
    #print(output)
    
    # Need to change this to csv output for easier data analysis. 
    with open(filepath, 'a') as outputfile:
        outputfile.write("----------------------------\n")
        outputfile.write("Found something GOOOOOD!\n")
        outputfile.write("ZIP file: {}\n".format(output['zip']))
        outputfile.write("Lambda File: {}\n".format(output['lamda']))
        outputfile.write("Description: {}\n".format(output['description']))
        outputfile.write("Line No: {}\n".format(output['line_no']))
        outputfile.write("Finding: {}\n".format(output['output']))
        if output.get('PossibleHosts') != None:
            outputfile.write("PossibleHosts: {}\n".format(output['PossibleHosts']))
        if output.get('PossibleUsers') != None:
            outputfile.write("PossibleUsers: {}\n".format(output['PossibleUsers']))
        if output.get('PossibleAccessKeys') != None:
            outputfile.write("PossibleAccessKeys: {}\n".format(output['PossibleAccessKeys']))
        if output.get('PossibleSessionTokens') != None:
            outputfile.write("PossibleSessionTokens: {}\n".format(output['PossibleSessionTokens']))
        outputfile.write("----------------------------\n")
        outputfile.write("\n")
    #print("afterprint")    