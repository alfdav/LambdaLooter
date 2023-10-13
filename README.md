# CLAWS - Credential Looter AWS

## Overview
Organizations can have thousands of lines of code that are stored in AWS across multiple services. This application was built to help reduce the amount of time it takes to review that code. What started as a necessity for pentesters to dig through lambda functions has morphed into a tool for both red and blue teamers to dig for creds throughout AWS services. Currently only supporting EC2 and Lambda, but with plans to expand to other services. 

LamdaLooter is a Python tool for AWS code analysis.

This script will analyze all AWS code that you have access to.

## configure AWS to get a list of your profiles
```
configure aws
cat ~/.aws/config | grep "\[profile" | cut -d " " -f 2 | cut -d "]" -f 1 >> AWSProfiles.txt
```
save the output of the above command to a text file

```
usage: LamdaLooter [-h] [--version] (-p PROFILE | -f PROFILELIST) [-r REGION] [-t THREADS] [-fv] [-d]

Download your Lambda code and scan for secrets.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p PROFILE, --profile PROFILE
                        Single AWS profile you want scan for lambda code
  -f PROFILELIST, --file PROFILELIST
                        File containing the AWS profiles you want scan for lambda code
  -r REGION, --region REGION
                        Your aws region you want to download lambda code from. Default=us-east-1.
  -t THREADS, --threads THREADS
                        Number of threads to download functions and scan for loot. Default=10.
  -fv, --versions       Download all versions of the Lambda code. Default=False.
  -d, --delete          Delete the Zip files after you are done looting. Default=False.

Download ---> Pillage ---> Loot ---> Prosper!
```
### Signatures
LambdaLooter relies on JSON files with signatures to determine what may be interesting. These signatures can be edited and changed depending on your own environment. 
* sig_all_tokens.json
    * contains signatures for all types of keys and tokens used on the web
* sig_basic_strings.json
    * contains basic strings we want to look for that may be interesting



