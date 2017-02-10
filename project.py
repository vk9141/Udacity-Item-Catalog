from flask import Flask, render_template, request, redirect, jsonify
from flask import url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Recipe, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "King Family Recipes"


# Connect to Database and create database session
engine = create_engine('sqlite:///categoryrecipeswithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 4010)
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
            json.dumps('Failed to upgrade the authorization code.'), 4011)
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
            json.dumps("Token's user ID doesn't match given user ID."), 4012)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 4013)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user already connected.'),
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
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' "style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Category Information
@app.route('/category/<int:category_id>/recipes/JSON')
def categoryRecipesJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    recipes = session.query(Recipe).filter_by(
        category_id=category_id).all()
    return jsonify(Recipes=[i.serialize_recipelist for i in recipes])


@app.route('/category/<int:category_id>/recipes/<int:recipe_id>/JSON')
def recipeJSON(category_id, recipe_id):
    Recipes_Recipe = session.query(Recipe).filter_by(id=recipe_id).one()
    return jsonify(Recipes_Recipe=Recipes_Recipe.serialize_recipe)


# Show all categories


@app.route('/')
@app.route('/category/')
def showCategories():
    categories = session.query(Category)
    return render_template('categories.html', categories=categories)


# Show recipes within a category


@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/recipes/')
def showRecipes(category_id):
    user_id = ""
    if 'username' in login_session:
        user_id = login_session['user_id']
    category = session.query(Category).filter_by(id=category_id).one()
    recipes = session.query(Recipe).filter_by(
        category_id=category_id).all()
    return render_template('recipes.html', recipes=recipes,
                           category=category, user_id=user_id)


# Recipe permalink


@app.route('/category/<int:category_id>/recipes/<int:recipe_id>/')
def showRecipe(category_id, recipe_id):
    user_id = ""
    if 'username' in login_session:
        user_id = login_session['user_id']
    category = session.query(Category).filter_by(id=category_id).one()
    recipe = session.query(Recipe).filter_by(id=recipe_id).one()
    return render_template('recipe.html', category_id=category_id,
                           recipe_id=recipe_id, item=recipe, user_id=user_id)


# Create a new recipe


@app.route('/category/<int:category_id>/recipes/new/', methods=['GET', 'POST'])
def newRecipe(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
            newRecipe = Recipe(name=request.form['name'],
                               description=request.form['description'],
                               ingredients=request.form['ingredients'],
                               instructions=request.form['instructions'],
                               category_id=category_id,
                               user_id=login_session['user_id'])
            session.add(newRecipe)
            session.commit()
            flash('New Recipe %s Successfully Created' % (newRecipe.name))
            return redirect(url_for('showRecipes', category_id=category_id))
    else:
        return render_template('newrecipe.html', category_id=category_id,
                               category=category)

# Edit a recipe


@app.route('/category/<int:category_id>/recipes/<int:recipe_id>/edit',
           methods=['GET', 'POST'])
def editRecipe(category_id, recipe_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedRecipe = session.query(Recipe).filter_by(id=recipe_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != editedRecipe.user_id:
        return "<script>function myFunction()", \
               " {alert('You are not authorized to edit');}", \
               "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedRecipe.name = request.form['name']
        if request.form['description']:
            editedRecipe.description = request.form['description']
        if request.form['ingredients']:
            editedRecipe.ingredients = request.form['ingredients']
        if request.form['instructions']:
            editedRecipe.instructions = request.form['instructions']
        session.add(editedRecipe)
        session.commit()
        flash('Recipe Successfully Edited')
        return redirect(url_for('showRecipes', category_id=category_id))
    else:
        return render_template('editrecipe.html', category_id=category_id,
                               recipe_id=recipe_id, item=editedRecipe)


# Delete a recipe


@app.route('/category/<int:category_id>/recipes/<int:recipe_id>/delete',
           methods=['GET', 'POST'])
def deleteRecipe(category_id, recipe_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    itemToDelete = session.query(Recipe).filter_by(id=recipe_id).one()
    if login_session['user_id'] != itemToDelete.user_id:
        return "<script>function myFunction()", \
               " {alert('You are not authorized to delete');}", \
               "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Recipe Successfully Deleted')
        return redirect(url_for('showRecipes', category_id=category_id))
    else:
        return render_template('deleteRecipe.html', item=itemToDelete)


# Disconnect


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
