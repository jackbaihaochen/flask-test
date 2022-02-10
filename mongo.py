import os
from dotenv import load_dotenv as env
from pymongo import MongoClient


def mongo_connection():
    HOST = os.getenv('MONGO_HOST', env('MONGO_HOST'))
    USERNAME = os.getenv('MONGO_USERNAME', env('MONGO_USERNAME'))
    PASSWORD = os.getenv('MONGO_PASSWORD', env('MONGO_PASSWORD'))
    AUTH = 'admin'
    PORT = 27017
    CONNECTION_URL = "mongodb://{username}:{password}@{host}:{port}/?authSource={auth}".format(username = USERNAME, password = PASSWORD, host = HOST, port = PORT, auth = AUTH)
    client = MongoClient(CONNECTION_URL)
    return client

def mongo_collection_connection():
    client = mongo_connection()
    db = client[os.getenv('MONGO_DB', env('MONGO_DB'))]
    collection = db[os.getenv('MONGO_COLLECTION', env('MONGO_COLLECTION'))]
    return collection

def mongo_insert_document(data):
    collection = mongo_collection_connection()
    collection.insert_one(data)
    print('Data Inserted.')

def mongo_update_document(query, new_data):
    collection = mongo_collection_connection()
    collection.update_one(query, {'$set': new_data})
    print('Data Updated.')