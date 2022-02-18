from flask import Flask, redirect
from flask import render_template
from flask import url_for
from flask import request
from mongo import mongo_collection_connection, mongo_connection
from lineworks import LineAuthV2
from lineworks import LineBot
from dotenv import load_dotenv as env
import json

app = Flask(__name__)

# For Line Works Bot
client_secret = 'O98Qf5Ic6O'
client_id = 'vd2Lb0QQvZ2ctU4qof7s'
service_account = 'nr2ca.serviceaccount@testcoltd-53'
# redirect_url = 'https://flask-test-bai.herokuapp.com/line_works/redirect_url'
redirect_url = 'http://127.0.0.1:5000/api/redirect'
new_bot_id = '3172234'
old_bot_id = '1416866'

# Auth Button Page
@app.route('/line_works/test_page')
def line_works_test_page():
    user_auth_url = LineAuthV2(client_secret = client_secret, client_id = client_id, service_account = service_account, redirect_url = redirect_url).user_auth_url
    return render_template('test_page.html', user_auth_url = user_auth_url)


# Redirect_URL for User Account Auth (OAuth)
# @app.route('/line_works/redirect_url', methods = ['GET'])
@app.route('/api/redirect', methods = ['GET'])
def line_works_redirect_url():
    authorization_code = request.args.get('code')
    # authorization_code = 'jp1WEVXVmJhYUQ1MXRLeUQ5ZA=='
    # state = request.args.get('state')
    # if(state == 'aBcDeF'):
    #     msg = 'State Matched'
    # else:
    #     msg = "Stata didn't Match"
    access_token = LineAuthV2(client_secret = client_secret, client_id = client_id, service_account = service_account, redirect_url = redirect_url).get_access_token(authorization_code = authorization_code)
    return render_template('redirect_url.html', authorization_code = authorization_code, access_token = access_token)

# Send Message to One certain user
@app.route('/line_works/send_to_one_user', methods = ['POST'])
def line_works_send_to_one_user():
    user_id = request.form['user_id']
    msg = request.form['msg']
    private_key = request.form['private_key']
    access_token = LineAuthV2(client_secret = client_secret, client_id = client_id, service_account = service_account, redirect_url = redirect_url, auth_type = 'JWT').get_access_token(private_key=private_key)
    if(access_token):
        result = LineBot(access_token, new_bot_id).send_text_message_to_one(user_id, msg)
        return result
    else:
        return 'No access token'

# Send Test Quick Reply to One certain user
@app.route('/line_works/send_quick_reply_to_one_user', methods = ['POST'])
def line_works_send_quick_reply_to_one_user():
    access_token = LineAuthV2(client_secret = client_secret, client_id = client_id, service_account = service_account, redirect_url = redirect_url).get_access_token()
    user_id = request.form['user_id']
    content_text = request.form['content_text']
    if(access_token):
        result = LineBot(access_token, new_bot_id).send_quick_reply_message_to_one(user_id, content_text)
        return result
    else:
        return 'No access token'

# Register a bot
@app.route('/line_works/register_one_bot', methods = ['POST'])
def line_works_register_one_bot():
    access_token = LineAuthV2(client_secret = client_secret, client_id = client_id, service_account = service_account, redirect_url = redirect_url).get_access_token()
    bot_name = request.form['bot_name']
    if(access_token):
        result = LineBot(access_token, new_bot_id).register_bot(bot_name)
        return result
    else:
        return 'Failed'

# Callback Handler for LINE WORKS
@app.route('/line_works/callback_url', methods = ['POST'])
def line_works_callback_url():
    response = request.json
    if(response is None):
        response = 'Nothing'
    access_token = LineAuthV2(client_secret = client_secret, client_id = client_id, service_account = service_account, redirect_url = redirect_url).get_access_token()
    LineBot(access_token, new_bot_id).callback_handler(response)
    return 'End'



@app.route('/jwt', methods = ['GET'])
def jwt():
    msg = LineAuthV2(client_secret, client_id, service_account, auth_type = "JWT").gen_line_service_auth_jwt()
    return render_template('hello.html', msg = msg)






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
    collection = mongo_collection_connection()
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
    collection = mongo_collection_connection()
    query = {
        'name': name
    }
    data = {
        'name': name,
        'age': age,
    }
    already_exist = collection.find_one_and_update(query, {'$set': data})
    if(not already_exist):
        document = collection.insert_one(data)
    return redirect(url_for('search_name', name = name))

if __name__ == '__main__':
    app.run()