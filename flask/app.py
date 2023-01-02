from flask import Flask, request, jsonify, redirect
from flask import render_template, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from json import loads
from dicttoxml import dicttoxml
import os
import json
import lxml.etree as etree


parser = etree.XMLParser(resolve_entities=True, no_network=False,huge_tree=True)
# Init app
app = Flask(__name__)
Flask.current_app = app
basedir = os.path.abspath(os.path.dirname(__file__))
# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# # Init db
with app.app_context():
    db = SQLAlchemy(app)
    # # Init ma
    ma = Marshmallow(app)

# Product Class/Model
class Product(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    qty = db.Column(db.Integer)

    def __init__(self, name, price, qty):
        self.name = name
        self.price = price
        self.qty = qty

# Product Schema
class ProductSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'price', 'qty')

# #User Class/Model
class User(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(100))

    def __init__(self, name, password, email):
        self.name = name
        self.password = password
        self.email = email

# User Schema
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'password', 'email')

# Init schema
product_schema = ProductSchema()
products_schema = ProductSchema(many=True)
user_scema = UserSchema()
users_schema = UserSchema(many=True)

def authenticate(email, password):
    # retrieve the user from the database
    user = User.query.filter_by(email=email, password=password).first()
    if user:
        print("user exist")
        return True
    else:
        print("nothing exists")
        return False
    # if the user does not exist, return False

# Create a User
@app.route('/signup', methods=['POST'])
def add_user():
    response = request.data
    
    print("response is,",response)

    #parser = etree.XMLParser(resolve_entities=True) # Noncompliant
    try:
        tree = etree.fromstring(response,parser=parser)
    except:
        result = {"message wrong type xml"}
        return jsonify({"status": "fail", "message": "Message wrong type XML"})
    # entity = tree.xpath("//*[@name='entity_name']")[0]

    # # Resolve the entity using the Entity class
    # resolved_entity = etree.Entity(entity)

    # # You can now use the resolved_entity object to access the link or any other information about the entity
    # link = resolved_entity.attrib['link']

    try:
        name = tree.find('name').text
        password = tree.find('password').text
        email = tree.find('email').text
    except Exception as e:
        result = {"message": "Name, password and email are required"}
        print(e)
        return jsonify({"status": "fail", "message": "Name, password and email are required"})

    user = User.query.filter_by(email=email).first()
    if user:
        result = {"message": "Email already exists"}
        print(result)
        return jsonify({"status": "fail", "message": "Email already exists", "user": name, "email": email})
    
    new_user = User(name, password, email)
    db.session.add(new_user)
    db.session.commit()

    result = {"message": str(name) + " created"}

    return jsonify({"status": "success", "user": name , "email": email, "message": "Logged in as " + email})
    # elems = tree.findall('name')
    # for elem in elems:
    #     print(elem.text)

@app.route('/login', methods=['POST'])
def login2():
    # if the user has submitted the form, try to authenticate
    print("request is,",request.method)
    response = request.data
    print("response is,",response)
    
    #parser = etree.XMLParser(resolve_entities=True) # Noncompliant
    tree = etree.fromstring(response, parser)

    try:
        password = tree.find('password').text
        email = tree.find('email').text
    except Exception as e:
        result = {"message": "Password and email are required"}
        print(e)
        return jsonify({"status": "fail", "message": "Password and email are required"})

    # authenticate the user
    if authenticate(email, password):
        # authentication was successful, redirect to a protected page
        print("now to new page")
        return jsonify({"status": 'success', "email": email, "message": "Logged in as " + email})
    else:
        # authentication failed, render the login page with an error message

        return jsonify({"status": 'fail', "email": email, "message": "Invalid credentials"})

#Get All Users
@app.route('/user', methods=['GET'])
def get_users():
    all_users = User.query.with_entities(User.name, User.email).all()
    result = jsonify(users_schema.dump(all_users))
    return dicttoxml(loads(result.data))

#Get Single User
@app.route('/user/<id>', methods=['GET'])
def get_user(id):
    user = User.query.filter_by(id=id).with_entities(User.name, User.email).one()
    result = user_scema.jsonify(user)
    return render_template('user.html', user=loads(result.data))

#Update a User
@app.route('/user/<id>', methods=['PUT'])
def update_user(id):
    user = User.query.get(id)

    response = request.data
    #parser = etree.XMLParser(resolve_entities=True) # Noncompliant
    tree = etree.fromstring(response, parser)

    name = tree.find('name').text
    password = tree.find('password').text
    email = tree.find('email').text

    user.name = name
    user.password = password
    user.email = email

    db.session.commit()

    result = user_scema.jsonify(user)

    return dicttoxml(loads(result.data))

# Delete User
@app.route('/user/<id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()

    result = user_scema.jsonify(user)

    return dicttoxml(loads(result.data))

# Create a Product
@app.route('/product', methods=['POST'])
def add_product():
    response = request.data
    #parser = etree.XMLParser(resolve_entities=True) # Noncompliant
    tree = etree.fromstring(response, parser)

    name = tree.find('name').text
    price = tree.find('price').text
    qty = tree.find('qty').text
    
    new_product = Product(name, price, qty)

    db.session.add(new_product)
    db.session.commit()

    result = product_schema.jsonify(new_product)

    return jsonify({"status": "success" ,"message": "Product created successfully", "productURL": 'product/' + str(id), "productName": name, "productPrice": price, "productQuantity": qty})

#Get All Products
# @app.route('/product', methods=['GET'])
# def get_products():
#     all_products = Product.query.all()
#     result = jsonify(products_schema.dump(all_products))
#     return dicttoxml(loads(result.data))

#Get All Product Names
@app.route('/productnames', methods=['GET'])
def get_product_names():
    all_products = Product.query.with_entities(Product.id, Product.name).all()
    result = jsonify(products_schema.dump(all_products))
    result = loads(result.data)
    new_result = []
    for product in result:
        new_result.append({product['id']: product['name']})
    return render_template('homepage.html', products=new_result)

#Get Single Product
@app.route('/product/<id>', methods=['GET'])
def get_product(id):
    product = Product.query.filter_by(id=id).with_entities(Product.name, Product.price, Product.qty).one()
    result = product_schema.jsonify(product)
    return render_template('product.html', product=loads(result.data))

#Update a Product
@app.route('/product/<id>', methods=['PUT'])
def update_product(id):
    product = Product.query.get(id)

    response = request.data
    #parser = etree.XMLParser(resolve_entities=True) # Noncompliant
    tree = etree.fromstring(response, parser)

    name = tree.find('name').text
    price = tree.find('price').text
    qty = tree.find('qty').text

    product.name = name
    product.price = price
    product.qty = qty

    db.session.commit()

    result = product_schema.jsonify(product)

    return dicttoxml(loads(result.data))

# Delete Product
@app.route('/product/<id>', methods=['DELETE'])
def delete_product(id):
    product = Product.query.get(id)
    db.session.delete(product)
    db.session.commit()

    result = product_schema.jsonify(product)

    return dicttoxml(loads(result.data))

@app.route('/login.html')
def login():
  return render_template('login.html')


@app.route('/signup.html')
def signup():
  return render_template('signup.html')

@app.route('/homepage.html')
def homepage():
  return render_template('homepage.html')

@app.route('/addproduct.html')
def addproductpage():
  return render_template('addproduct.html')

@app.route('/')
def index():
  return render_template('index.html')


# @app.route('/homepage.html')
# def homepage():
#     retrieve all products from the database
#     products = Product.query.all()
#     render the homepage template and pass the products as a variable
#     return render_template('homepage.html', products=products)

# Run Server
if __name__ == '__main__':
   
    app.run(debug=True)

