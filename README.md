# CLAWS - Credential Looter AWS


Organizations can have millions of lines of code that are stored in AWS across multiple services. This application was built to help reduce the amount of time it takes to review that code. What started as a necessity for pentesters to dig through lambda functions has morphed into a tool for both red and blue teamers to dig for creds throughout AWS services.  


## Input:

accounts.txt is the current file. One profileID per line
```
    12354678912
    98745612356
    46512378925

```


## Usage:

```
usage: claws [-h] [--version] (-p PROFILE) [-r REGION] [-t THREADS] [-fv] [-d] [-ro ROLE] [-hu] [-l] [-e] [-s]

Download your Lambda code and scan for secrets.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p PROFILE, --profile PROFILE
                        Single AWS profile you want scan for lambda code
  -r REGION, --region REGION
                        Your aws region you want to download lambda code from. Default=us-east-1.
  -t THREADS, --threads THREADS
                        Number of threads to download functions and scan for loot. Default=10.
  -fv, --versions       Download all versions of the Lambda code. Default=False.
  -d, --delete          Delete the Zip files after you are done looting. Default=False.
  -ro, --role           Role that you will use if trying to assume role chain.
  -hu, --hunt           Hunt through all code in /loot.
  -l, --lambda          Download Lambda code.
  -e, --ec2             Download EC2 UserData code. (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html)
  -s, --ssm             Download SSM documents. (https://docs.aws.amazon.com/systems-manager/latest/userguide/documents.html)

Download ---> Pillage ---> Loot ---> Prosper!
```
### Signatures:
LambdaLooter relies on JSON files with signatures to determine what may be interesting. These signatures can be edited and changed depending on your own environment. 
* sig_all_tokens.json
    * contains signatures for all types of keys and tokens used on the web


## Required IAM permissions:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "lambda:ListFunctions",
                "lambda:GetFunction",
                "lambda:GetFunctionConfiguration",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeInstances",
                "ssm:ListDocuments",
                "ssm:GetDocument",
                "ssm:DescribeDocument"
            ],
            "Resource": "*"
        }
    ]
}
```



## Change Logs for CLAWS v1.1:
* Now Supports SSM document looting
* Now supports EC2 UserData looting
* Output changes
    * All output is within json files inside of the ../findings folder
    * All output is currently in json format.
    * All findings are initially in notvalidated.json
* Tracking
    * Tracking has been enabled per AWS account ID.
    * These files will track the last time Lambda, EC2, or SSM data was downloaded and only download code that has changed since then.
    * Can be found in ../track
* Multi-Threading Changes
    * Multi-threading is now only enabled on Downloading code. This is due to multi-threading actually being worse for regex activity. 
    * A single python script uses one core. Multi-threading does not chanmge the number of cores, simply the number of threads on a single core. Regexing without multithreading already maxes out the core it is running on. By multi-threading, you are only adding more overhead for the cpu to handle rather than allowing all it's processing power be for regexing. 
* Removal of basic string searches
    * From my research, using regex for simple text searches is generally as intensive as other string searches. 
    * Open to changing it back to allow for simple strings as with regex, cancellations may be required for special characters. 
* Logs
  * Duplicates
      * Duplicates are checked based on sha2 of the secret seen. 
      * Duplicates are blasted as a log to ../logs/duplicates.log
  * Failures
      * Most failures are logged in ../logs/failures.log
* SecretHandler.py
  * This python script can be used to call speciifc credentials from wherever you may be keeping them. 
  * There is a working secretsmanager function in it for those using secretsmanager
* SecretValidation.py
  * Handles the output for each finding
  * Handles additional searches needed for findings such as AKIA's additional searches
  * Additional advanced options:
    * You can create your own credential verification functions within this python script 
    * Understand the creds and applications that exist in your company and work on creating a flow that will utilize an API or some other way to verify whether the credential found is legitimate. 
    * Verifying credentials can help you automate emails to individuals you know has exposed a cred and get them changing it as soon as possible. 

## Future Plans:
* Change output
    * Update output to be JSONL isntead of JSON. 
    * This should allow for better munipulation of the output by grep and other means. 
* Configuration file
    * Many things could become configurable variables by creating a configuration file. 
    * This would be extremely helpful for multiple environments. (Running a test and a prod version with different accounts in a list.)
    * Would also shorten the command line arguments. 
* Streamline failure logs?
    * The logging could be made easier. Feels like something we should maybe look into for failures.
* Check other potential things to download?
    * ECS
    * Code Deploy
    * Sagemaker
* Duplicates updates
    * Change duplicates to check all .json/jsonl files in /findings for duplicates
    * This will allow for organization of findings into separate lists if needed. 



