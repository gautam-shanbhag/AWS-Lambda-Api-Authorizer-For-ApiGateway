import jwt
from jwt import PyJWKClient
import os
import json

print("--- API AUTHORIZER ---")

env = json.loads(os.environ['ENV'])

#aud = json.loads(os.environ['audience'])
#client_id = json.loads(os.environ['client_id'])
#scope = json.loads(os.environ['scope'])
#iss = json.loads(os.environ['issuer'])
#jwks_url = json.loads(os.environ['jwks_url'])
#resource = json.loads(os.environ['api_gateway_resource'])
#principal_id = json.loads(os.environ['policy_principal_id'])

aud = env['audience']
client_id_list = env['client_id'].split(",")
client_id = []
for i in client_id_list:
    id = i.replace(' ', '')
    client_id.append(id)
scope = env['scope']
iss = env['issuer']
jwks_url = env['jwks_url']
resource = env['api_gateway_resource']
principal_id = env['policy_principal_id']

def lambda_handler(event, context):
    print('Event : ')
    print(event)

    print('Environment Variables : ')
    print(env)

    auth = 'Deny'
    try:
        if "authorizationToken" in event:
            authToken = event['authorizationToken']
            parts = authToken.split()

            if parts[0].lower() != "bearer":
                raise Exception({"code": "invalid_header",
                                 "description": "Authorization header must start with Bearer"
                                 }, 401)
            if len(parts) == 1:
                raise Exception({"code": "invalid_header",
                                 "description": "Token not found"
                                 }, 401)
            if len(parts) > 2:
                raise Exception({"code": "invalid_header",
                                 "description": "Authorization header must be Bearer token"
                                 }, 401)

            token = parts[1]

            jwks_client = PyJWKClient(jwks_url)
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(jwt=token, key=signing_key.key, algorithms=["RS256"], audience=aud, issuer=iss,
                                options={"verify_signature": True})

            if claims['client_id'] not in client_id:
                raise Exception({"code": "invalid_token",
                                 "description": "Invalid Client Id"
                                 }, 401)
            if claims['scope'] != scope:
                raise Exception({"code": "invalid_token",
                                 "description": "Invalid Scope"
                                 }, 401)
            print(claims)
            auth = 'Allow'

    except Exception as e:
        print("Invalid")
        print(f"Exception caught. Error: {e}")
        auth = 'Deny'

    authResponse = {"principalId": principal_id, "policyDocument":
        {"Version": "2012-10-17", "Statement":
            [
                {"Action": "execute-api:Invoke",
                 "Effect": auth,
                 "Resource": resource
                 }
            ]
         }
                    }
    print(authResponse)
    print("--- API AUTHORIZER : Success ---")

    return authResponse