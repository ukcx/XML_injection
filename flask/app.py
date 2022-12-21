from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from json import loads
from dicttoxml import dicttoxml
import os
import xml.etree.ElementTree as ET

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
    description = db.Column(db.String(200))
    price = db.Column(db.Float)
    qty = db.Column(db.Integer)

    def __init__(self, name, description, price, qty):
        self.name = name
        self.description = description
        self.price = price
        self.qty = qty

# Product Schema
class ProductSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'description', 'price', 'qty')

# #User Class/Model
class User(db.Model):
    id = db.Column(db.Integer, unique=True,primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    address = db.Column(db.String(100))

    def __init__(self, name, email, address):
        self.name = name
        self.email = email
        self.address = address

# User Schema
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'email', 'address')

# Init schema
product_schema = ProductSchema()
products_schema = ProductSchema(many=True)
user_scema = UserSchema()
users_schema = UserSchema(many=True)

# Create a User
@app.route('/user', methods=['POST'])
def add_user():
    response = request.data
    tree = ET.fromstring(response)

    name = tree.find('name').text
    email = tree.find('email').text
    address = tree.find('address').text
    new_user = User(name, email, address)
    db.session.add(new_user)
    db.session.commit()

    result = user_scema.jsonify(new_user)

    return dicttoxml(loads(result.data))
    # elems = tree.findall('name')
    # for elem in elems:
    #     print(elem.text)

#Get All Users
@app.route('/user', methods=['GET'])
def get_users():
    all_users = User.query.all()
    result = jsonify(users_schema.dump(all_users))
    return dicttoxml(loads(result.data))

#Get Single User
@app.route('/user/<id>', methods=['GET'])
def get_user(id):
    user = User.query.get(id)
    result = user_scema.jsonify(user)
    return dicttoxml(loads(result.data))

#Update a User
@app.route('/user/<id>', methods=['PUT'])
def update_user(id):
    user = User.query.get(id)

    response = request.data
    tree = ET.fromstring(response)

    name = tree.find('name').text
    email = tree.find('email').text
    address = tree.find('address').text

    user.name = name
    user.email = email
    user.address = address

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
    tree = ET.fromstring(response)

    name = tree.find('name').text
    description = tree.find('description').text
    price = tree.find('price').text
    qty = tree.find('qty').text
    
    new_product = Product(name, description, price, qty)

    db.session.add(new_product)
    db.session.commit()

    result = product_schema.jsonify(new_product)

    return dicttoxml(loads(result.data))

#Get All Products
@app.route('/product', methods=['GET'])
def get_products():
    all_products = Product.query.all()
    result = jsonify(products_schema.dump(all_products))
    return dicttoxml(loads(result.data))

#Get Single Product
@app.route('/product/<id>', methods=['GET'])
def get_product(id):
    product = Product.query.get(id)
    result = product_schema.jsonify(product)
    return dicttoxml(loads(result.data))

#Update a Product
@app.route('/product/<id>', methods=['PUT'])
def update_product(id):
    product = Product.query.get(id)

    response = request.data
    tree = ET.fromstring(response)

    name = tree.find('name').text
    description = tree.find('description').text
    price = tree.find('price').text
    qty = tree.find('qty').text

    product.name = name
    product.description = description
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

# Run Server
if __name__ == '__main__':
    app.run(debug=True)

