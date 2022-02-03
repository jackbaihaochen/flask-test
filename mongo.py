import os
from pymongo import MongoClient
def mongo_connection():
    HOST = os.getenv('MONGO_HOST')
    USERNAME = os.getenv('MONGO_USERNAME')
    PASSWORD = os.getenv('MONGO_PASSWORD')
    AUTH = 'admin'
    PORT = 27017
    CONNECTION_URL = "mongodb://{username}:{password}@{host}:{port}/?authSource={auth}".format(username = USERNAME, password = PASSWORD, host = HOST, port = PORT, auth = AUTH)
    client = MongoClient(CONNECTION_URL)
    return client