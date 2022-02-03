from flask import Flask, redirect
from flask import render_template
from flask import url_for
from flask import request
from mongo import mongo_connection
import lineworks

app = Flask(__name__)

# For Line Works Bot
# Auth Button Page
@app.route('/line_works/test_page')
def line_works_test_page():
    client_secret = 'dFVoTijl9l'
    client_id = 'AVd_gv8Ruji_80dWUNRt'
    service_account = '6xr6v.serviceaccount@jackbai'
    redirect_url = 'https://ec2-3-82-201-32.compute-1.amazonaws.com:5000/line_works/redirect_url'
    user_auth_url = lineworks.LineAuthV2(client_secret = client_secret, client_id = client_id, service_account = service_account, redirect_url = redirect_url).user_auth_url
    return render_template('test_page.html', user_auth_url = user_auth_url)


# Redirect_URL for User Account Auth (OAuth)
@app.route('/line_works/redirect_url', methods = ['GET'])
def line_works_redirect_url():
    authorization_code = request.args.get('code')
    state = request.args.get('state')
    if(state == 'aBcDeF'):
        msg = 'State Matched'
    else:
        msg = "Stata didn't Match"
    return render_template('redirect_url.html', msg = msg, state = state, authorization_code = authorization_code)

# For basic test
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
        if(not name):
            raise KeyError
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