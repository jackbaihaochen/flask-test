from flask import Flask, redirect
from flask import render_template
from flask import url_for
from flask import request
from mongo import mongo_connection
from lineworks import LineAuthV2

app = Flask(__name__)

# For Line Works Bot
client_secret = 'dFVoTijl9l'
client_id = 'AVd_gv8Ruji_80dWUNRt'
service_account = '6xr6v.serviceaccount@jackbai'
redirect_url = 'https://flask-test-bai.herokuapp.com/line_works/redirect_url'

# Auth Button Page
@app.route('/line_works/test_page')
def line_works_test_page():
    user_auth_url = LineAuthV2(client_secret = client_secret, client_id = client_id, service_account = service_account, redirect_url = redirect_url).user_auth_url
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
    access_token = LineAuthV2(client_secret = client_secret, client_id = client_id, service_account = service_account, redirect_url = redirect_url).get_access_token(authorization_code = authorization_code)
    return render_template('redirect_url.html', msg = msg, state = state, authorization_code = authorization_code, access_token = access_token)

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

if __name__ == '__main__':
    app.run()