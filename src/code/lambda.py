import json
import psycopg2
import boto3
import os
import jwt
import datetime
import sys
import bcrypt

def main(event, context):
    print('chegou no lambda')
    statusCode = 401,
    body = json.dumps({
        "message": "Unauthorized: Missing or invalid authentication credentials."
    })

    if 'body' in event:
        print('tem body')
        request_body = json.loads(event['body'])
        if 'registration' and 'password' in request_body:
            print('tem reg e password')
            registration = request_body['registration']
            password = request_body['password']
            result = get_password(registration)
            if result:
                print('tem result: ',result)
                if verify_password(result[0], password):
                    jwt = build_jwt(registration)
                    statusCode = 200
                    body = json.dumps({
                        "token": jwt
                    })
                else:
                    body = json.dumps({
                        "message": "Wrong password"
                    })
            else:
                body = json.dumps({
                    "message": "User not found"
                })
    response = {
        "statusCode": statusCode,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": body
    }
    return response

def get_secrets(secret_name):
    try:
        print('vai recuperar os secrets: ', secret_name)
        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name='us-east-1'
        )
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        secret = json.loads(get_secret_value_response['SecretString'])    
        return secret
    except Exception as e:
        print("Error! ", e)
        sys.exit(1) 

def get_password(registration):
    try:
        print('vai conectar ao DB')
        #Get secrets
        secret = get_secrets(os.environ['SECRET_NAME'])
        print('secrets: ', secret)
        db_username = secret['username']
        db_password = secret['password']
        db_name = secret['dbname']
        db_host = secret['host']
        db_port = secret['port']

        #DB connection
        connection = psycopg2.connect(
            host=db_host,
            dbname=db_name,
            user=db_username,
            password=db_password,
            port=db_port
        )
        cursor = connection.cursor()
        print("Connected to the database")

        #Build and Query
        query = "SELECT password FROM users WHERE registration=%s"
        cursor.execute(query, (registration,))

        # Fetch the results
        result = cursor.fetchone()
        print('resultado: ', result)

        #Close connection
        cursor.close()
        connection.close()
        print("Database connection closed")

        return result
    except Exception as e:
        print("Error! ", e)
        sys.exit(1)

def build_jwt(cpf):
    try:
        print("build jwt")
        #Get secret
        secret = get_secrets(os.environ['SECRET_KEY_AUTH'])
        key = secret['secret_key']
        expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        payload = {
            "cpf": cpf,
            "exp": expiration_time
        }
        jwt_token = jwt.encode(
            payload,
            key,
            algorithm='HS256',          
        )
        return jwt_token
    except Exception as e:
        print("Error! ", e)
        sys.exit(1)

def verify_password(hashed_password, password):
    print('password: , hash_password: ', password, hashed_password)
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    