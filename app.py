from flask import Flask, render_template
from flask import session as login_session
from flask import make_response
from flask import request
from flask import flash
from flask import redirect
from flask import jsonify

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, joinedload
from database_setup import Base, User, Category, Food

from database_setup import Base

import random
import string
import httplib2
import json
import requests

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())[
    'web']['client_id']

# Setup flask
app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

# Seems to be a problem with this.
# Will init in each utilized method per Udacity knowledge base question 11878
# DBSession = sessionmaker(bind=engine)
# session = DBSession()


# Helper Methods

def BuildNewState():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    return state


# API
# Food Category Routes

@app.route('/api/v1/categories')
def getCategories():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    results = session.query(Category).all()
    return jsonify(categories=[i.serialize for i in results])


@app.route('/api/v1/categories/<int:id>')
def getCategory(id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    category = session.query(Category).get(id)

    if category is None:
        return jsonify({'error': 'Category not found.'}), 400

    return jsonify(category=category.serialize)


@app.route('/api/v1/categories', methods=['POST'])
def addCategory():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    if 'username' not in login_session:
        return jsonify({'error': 'You must be logged in to modify data.'}), 401

    if (request.form['category'] is None):
        response = make_response(json.dumps(
            'Category parameter required.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    category = Category(category=request.form['category'])
    session.add(category)
    session.commit()

    if (request.form.get('render-html') is not None):
        return render_template('categories.html')
    else:
        return jsonify(category=category.serialize)


@app.route('/api/v1/categories/<int:id>', methods=['PUT'])
def updateCategory(id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    if 'username' not in login_session:
        return jsonify({'error': 'You must be logged in to modify data.'}), 401

    category = session.query(Category).get(id)

    if category is None:
        return jsonify({'error': 'Category not found.'}), 400

    if request.form['update-category']:
        category.category = request.form['update-category']
        session.commit()
        return jsonify(category=category.serialize)
    return jsonify({'Notice': 'No records were updated'}), 400


@app.route('/api/v1/categories/<int:id>', methods=['DELETE'])
def deleteCategory(id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    if 'username' not in login_session:
        return jsonify({'error': 'You must be logged in to modify data.'}), 401

    category = session.query(Category).get(id)

    if category is None:
        return jsonify({'error': 'Category not found.'}), 400

    session.delete(category)
    session.commit()

    return jsonify({'success': 'The category has been deleted'})


@app.route('/api/v1/categories/food')
def getFoodByCategory():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    results = session.query(Category).options(joinedload(Category.food)).all()
    return jsonify(Categories=[dict(c.serialize,
                                    Food=[i.serialize for i in c.food])
                               for c in results])


# Food Routes
@app.route('/api/v1/food')
def getAllFood():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    results = session.query(Food).all()
    return jsonify(food=[i.serialize for i in results])


@app.route('/api/v1/food/<int:id>')
def getFood(id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    food = session.query(Food).get(id)

    if food is None:
        return jsonify({'error': 'Food not found.'}), 400

    return jsonify(food=food.serialize)


@app.route('/api/v1/food', methods=['POST'])
def addFood():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    if 'username' not in login_session:
        return jsonify({'error': 'You must be logged in to modify data.'}), 401

    if (request.form['insert-name'] is None):
        response = make_response(json.dumps(
            'Food name parameter required.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    food = Food(name=request.form['insert-name'],
                description=request.form['insert-description'],
                category_id=request.form['insert-category'])
    session.add(food)
    session.commit()

    if (request.form.get('render-html') is not None):
        return render_template('food.html')
    else:
        return jsonify(food=food.serialize)


@app.route('/api/v1/food/<int:id>', methods=['PUT'])
def updateFood(id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    print(id)
    if 'username' not in login_session:
        return jsonify({'error': 'You must be logged in to modify data.'}), 401

    food = session.query(Food).get(id)

    if food is None:
        return jsonify({'error': 'Food not found.'}), 400

    if request.form['update-food']:
        food.name = request.form['update-food']
    if request.form['update-category']:
        food.category_id = request.form['update-category']
    if request.form['update-description']:
        food.description = request.form['update-description']

    session.commit()
    return jsonify(food=food.serialize)


@app.route('/api/v1/food/<int:id>', methods=['DELETE'])
def deleteFood(id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    if 'username' not in login_session:
        return jsonify({'error': 'You must be logged in to modify data.'}), 401

    food = session.query(Food).get(id)

    if food is None:
        return jsonify({'error': 'Food not found.'}), 400

    session.delete(food)
    session.commit()

    return jsonify({'success': 'The food has been deleted'})

# Views


@app.route('/')
def displayHome():
    return render_template('home.html')


@app.route('/categories')
def displayCategories():
    return render_template('categories.html')


@app.route('/food')
def displayFood():
    return render_template('food.html')


@app.route('/login')
def displayLogin():
    state = BuildNewState()
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# Login Routes
# Oauth code was written while taking the Udacity Full-stack Back-end courses.
# Credit goes to Udacity for oauth implementation


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    print(request.args.get('state'))
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']

    # Add user to database if they don't already exist
    user_id = getUserID(data['email'])

    if user_id is None:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h3>Welcome, '
    output += login_session['username']
    output += '!</h3>'
    flash("you are now logged in as %s" % login_session['username'])

    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    url = """https://accounts.google.com
            /o/oauth2/revoke?token=%s""" % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        return redirect('/login')
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'))
        response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s " % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = """https://graph.facebook.com/oauth/access_token
            ?grant_type=fb_exchange_token
            &client_id=%s&client_secret=%s&fb_exchange_token=%s""" % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # formatting the token
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = """https://graph.facebook.com/v2.8/me
            ?access_token=%s&fields=name,id,email""" % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # see if user exists
    user_id = getUserID(login_session['email'])
    if user_id is None:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h3>Welcome, '
    output += login_session['username']
    output += '!</h3>'

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    h.request(url, 'DELETE')[1]

    del login_session['username']
    del login_session['email']
    del login_session['facebook_id']

    return redirect('/login')

# User Helper Functions


def createUser(login_session):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    print(login_session['username'])
    print(login_session['email'])

    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
