import os
import json
import requests
from datetime import datetime, date
import random
import string
from pprint import pprint
from hashlib import sha256
import secrethandler


scriptname = 'nonvalidatedstats.py'


def main():
    notvalidated()

def notvalidated():
    filepath = '../findings/notvalidated.json'
    nonSubmittedFile = os.path.isfile(filepath)
    if nonSubmittedFile:
        subJSON = json.load(open(filepath))
        for pos,sub in enumerate(subJSON['unvalidated']):
            #print(sub['exposed_cred']['secret'])
            if sub['exposed_cred']['cred_type'].startswith('vault'):
                print(sub['exposed_cred']['secret'])
                #obvFalsePositive(sub)
                #removeFromNotValidated(sub)


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

