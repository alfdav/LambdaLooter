import os
import json
import requests
from datetime import datetime, date
import random
import string
from pprint import pprint
from hashlib import sha256
import secrethandler
import base64
import time

scriptname = 'nonvalidatedstats.py'

'''
 'date_found': '2024-04-20',
 'exposed_cred': {'cred_type': 'vault client token',
                  'identity': '',
                  'secret': 's.xxxxxxxxxxxxxxxxxxxx',
                  'secret_extra': ''},
 'project_path': 'lambda',
 'provider': 'CLAWS',
 'sha2': 'f367e1f20431fdefbd2eabddc9081a3ee0de4b62fe058ec41fd291de4f5aa2c7',
 'source': 'dist/index.js',
 'stepFunctionId': 'claws45712453059613995967349434246264',
 'visibility': ''}'''




def main():
    expirecheck()
    #JWTlook()

def JWTlook():
    filepath = '../findings/notvalidated.json'
    nonSubmittedFile = os.path.isfile(filepath)
    if nonSubmittedFile:
        subJSON = json.load(open(filepath))
        for pos,sub in enumerate(subJSON['unvalidated']):
            if sub['exposed_cred']['secret'].startswith('eyJ'):
                print(sub['exposed_cred']['secret'].split('.'))
                JWT = sub['exposed_cred']['secret'].split('.')[1]
                #pprint(sub)
                print(JWT)
                if 'John Doe' in str(JWT):
                    print('yes')
                parsed = parseJWT(JWT)
                if parsed == None or parsed.get('exp') == None:
                    continue
                pprint(parsed.get('exp'))
                #expired = isexpired(parsed.get('exp'))




def expirecheck():
    filepath = '../findings/notvalidated.json'
    nonSubmittedFile = os.path.isfile(filepath)
    if nonSubmittedFile:
        subJSON = json.load(open(filepath))
        for pos,sub in enumerate(subJSON['unvalidated']):
            if sub['exposed_cred']['secret'].startswith('eyJ'):
                JWT = sub['exposed_cred']['secret'].split('.')[1]
                #print(JWT)
                parsed = parseJWT(JWT)
                if parsed == None or parsed.get('exp') == None:
                    continue
                pprint(parsed.get('exp'))
                expired = isexpired(parsed.get('exp'))
                print(expired)
                if expired:
                    expiredlistadd(sub)                                            
                    
                #obvFalsePositive(sub)
                    removeFromNotValidated(sub)

def isexpired(exp):
    epoch = int(time.time())
    exp = int(exp)
    if exp > epoch:
        print('Not expired')
        return False
    else:
        print(f'{exp} not greater than {epoch}')
        return True

def parseJWT(JWT):
    sample = base64.b64decode(str(JWT) + "==")
    print(sample)
    decodedsample = None
    try:
        decodedsample = sample.decode("ascii")
    except UnicodeDecodeError:
        try:
            decodedsample = sample.decode("utf-8")
        except UnicodeDecodeError as e:
            print(e)
    if decodedsample != None:
        return json.loads(decodedsample)
    else:
        return None
    
def expiredlistadd(subInfo):
    print('expiredJWT()')
    filepath = '../findings/expiredJWT.json'
    submittedFile = os.path.isfile(filepath)
    if submittedFile:
        subJSON = json.load(open(filepath))
        subJSON['expired'].append(subInfo)
    else:
        subJSON = {'expired':[subInfo]}
    #pprint(subJSON)
    with open(filepath, 'w') as jf:
        jf.write(json.dumps(subJSON))
    

def updateNotValidated(subInfo):
    filepath = '../findings/notvalidated.json'
    submittedFile = os.path.isfile(filepath)
    with open(filepath, 'w') as jf:
        jf.write(json.dumps(subInfo))
    
def check(sub):
    for every in s_checks:
        if every.upper() in sub['exposed_cred']['secret'].upper():
            print(sub['exposed_cred']['secret'])
            removeFromNotValidated(sub)
            obvFalsePositive(sub)

def obvFalsePositive(subInfo):
    print('logSubmission()')
    filepath = '../findings/obvfalsepositive.json'
    submittedFile = os.path.isfile(filepath)
    if submittedFile:
        subJSON = json.load(open(filepath))
        subJSON['obvfalsepositive'].append(subInfo)
    else:
        subJSON = {'obvfalsepositive':[subInfo]}
    #pprint(subJSON)
    with open(filepath, 'w') as jf:
        jf.write(json.dumps(subJSON))


def removeFromNotValidated(subInfo):
    filepath = '../findings/notvalidated.json'
    notsubmittedFile = os.path.isfile(filepath)
    if notsubmittedFile:
        subJSON = json.load(open(filepath))
        for pos,each in enumerate(subJSON['unvalidated']):
            if each['sha2'] == subInfo['sha2']:
                pprint(each)
                del subJSON['unvalidated'][pos]
    with open(filepath, 'w') as jf:
        jf.write(json.dumps(subJSON))
    #pprint(subJSON)


if __name__ == "__main__":
    main()

