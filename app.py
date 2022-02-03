from flask import Flask, redirect
from flask import render_template
from flask import url_for
from flask import request

app = Flask(__name__)

@app.route('/', methods = ['GET'])
def show_search():
    name = request.args.get('name')
    age = request.args.get('age')
    msg = request.args.get('msg')
    return render_template('hello.html', search_url = url_for('search_name'), show_insert_url = url_for('show_insert'), name = name, age = age, msg = msg)

@app.route('/show_insert', methods = ['GET'])
def show_insert():
    msg = request.args.get('msg')
    return render_template('insert.html', insert_url = url_for('insert_name'), show_search_url = url_for('show_search'), msg = msg)

@app.route('/search_name', methods = ['GET'])
def search_name():
    try:
        name = request.args['name']
    except KeyError:
        return redirect(url_for('show_search', msg = 'Please enter name.'))
    client = mongo_connection()
    db = client['test-db']
    collection = db['test-collection']
    document = collection.find_one({'name':name})
    if(document):
        try:
            age = document['age']
            return redirect(url_for('show_search', name = name, age = age))
        except KeyError:
            return redirect(url_for('show_search', msg = 'Search Error.'))
    else:
        return redirect(url_for('show_search', msg = 'Name not found.'))


@app.route('/insert_name', methods = ['POST'])
def insert_name():
    try:
        name = request.form['name']
        age = request.form['age']
    except KeyError:
        return redirect(url_for('show_insert', msg = 'Enter Error.'))
    client = mongo_connection()
    db = client['test-db']
    collection = db['test-collection']
    data = {
        'name': name,
        'age': age,
    }
    document = collection.insert_one(data)
    return redirect(url_for('show_search', name = name, age = age))

def mongo_connection():
    import os
    from pymongo import MongoClient
    HOST = os.getenv('MONGO_HOST')
    USERNAME = os.getenv('MONGO_USERNAME')
    PASSWORD = os.getenv('MONGO_PASSWORD')
    AUTH = 'admin'
    PORT = 27017
    CONNECTION_URL = "mongodb://{username}:{password}@{host}:{port}/?authSource={auth}".format(username = USERNAME, password = PASSWORD, host = HOST, port = PORT, auth = AUTH)
    client = MongoClient(CONNECTION_URL)
    return client