import os
import json
import requests
import msal

# This is a placeholder script to handle any secret fetching that needs to happen.
# Utilize this secret script to get secrets to your DB holding all your aws accounts. Or utilize it to call another app to help verify a credential or identity. 
# Grab a token to fetch who the owners are for a specific account or grab the API key to query logs for a specific identity. 
def main():
    print('main()')

def getBearerToken(cred):
    # Client ID from Consuming app
    CONSUMER_API_APP_ID = '<App ID with access to get bearer token from azure>'

    # Scope is for the app being consumed
    API_SCOPE  = '<app id that you want the bearer token for>'
    AZURE_TENANT = 'https://login.microsoftonline.com/<insert tennant id here>'

    bearerToken = msal.ConfidentialClientApplication(CONSUMER_API_APP_ID, client_credential=cred, authority=AZURE_TENANT).acquire_token_for_client([API_SCOPE]).get('access_token')
    return bearerToken


def getToken():
    #print('getToken()')
    token = os.popen(f"<linux or windows commandline that gets a cred or token of some sort>")
    return token.read()

# grabbing secret for secretsmanager in AWS.
# This will work out of the box if you pass the correct variables and have the needed role for hte accesses. 
def getSecret(secret_name, region_name):
    #print('getSecret()')

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = get_secret_value_response['SecretString']
    return secret

if __name__ == "__main__":
    main()


