from functools import wraps
import os, datetime
from flask import Flask, request, make_response, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
import utils.load_env as load_env
from utils.pyjwt import sign_token, verify_token as verify_jwt_token
from model import summarize
from flask_cors import CORS

load_env.load()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

app.config['CORS_HEADERS'] = ['Content-Type']
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class UserModel(db.Model):
    ph = PasswordHasher()
    __tablename__ = "users"

    id = db.Column("id", db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(65), nullable=False)
    email = db.Column(db.String(245), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    api_key = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    def __init__(self, name, email, password, api_key=None):
        self.name = name
        self.email = email
        self.api_key = api_key
        
        # Hash password before saving
        self.password = self.ph.hash(password)

@app.route("/healtcheck", methods=["GET"])
def healtcheck():
    data = {
        "code": 200,
        "status": "OK"
    }
    return jsonify(data)

@app.route("/", methods=["GET"])
def index():
    return "Hello, World"

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if token is None:
            return jsonify({
                "code": 401,
                "status": "Unauthorized",
                "errors": [
                    {
                        "error": "Missing X-API-KEY in headers"
                    }
                ]
            }), 401

        data = verify_jwt_token(token)

        if data is None:
            return jsonify({
                "code": 401,
                "status": "Unauthorized",
                "errors": [
                    {
                        "error": "Invalid X-API-KEY"
                    }
                ]
            }), 401
        
        # Set the user to the request object
        request.user = data

        return f(*args, **kwargs)

    return decorated

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = None

        if 'X-API-KEY' in request.headers:
            api_key = request.headers['X-API-KEY']

        if api_key is None:
            return jsonify({
                "code": 401,
                "status": "Unauthorized",
                "errors": [
                    {
                        "error": "Missing X-API-KEY in headers"
                    }
                ]
            }), 401
        
        # Get the logged in user from prev middleware
        user = request.user
        
        # Verify the API key
        user = UserModel.query.filter_by(email=user['email']).first()

        if user.api_key != api_key is False:
            return jsonify({
                "code": 401,
                "status": "Unauthorized",
                "errors": [
                    {
                        "error": "Invalid X-API-KEY"
                    }
                ]
            }), 401

        if user is None:
            return jsonify({
                "code": 401,
                "status": "Unauthorized",
                "errors": [
                    {
                        "error": "Invalid X-API-KEY"
                    }
                ]
            }), 401

        return f(*args, **kwargs)

    return decorated

@app.route("/api/v1/auth", methods=["POST"])
def signin():
    body = request.get_json()

    # Check the if the user exists
    user = UserModel.query.filter_by(email=body['email']).first()

    if user is None:
        data = {
            "code": 401,
            "status": "Unauthorized",
            "errors": [
                {
                    "error": "Invalid email or password"
                }
            ]
        }

        return jsonify(data), 401

    # Verify the password
    ph = UserModel.ph
    try:
        ph.verify(user.password, body['password'])
    except:
        data = {
            "code": 401,
            "status": "Unauthorized",
            "errors": [
                {
                    "error": "Invalid email or password"
                }
            ]
        }

        return jsonify(data), 401

    eight_hours = datetime.datetime.now() + datetime.timedelta(hours=8)

    # Sign a JWT token
    payload = {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        # 8 hours
        "exp": eight_hours.timestamp()
    }

    token = sign_token(payload)
    print("Token: " + token)

    # resp = make_response()
    # resp.set_cookie('token', token, httponly=True, expires=eight_hours)

    # return resp.redirect("/auth/redirect")

    return jsonify({
        "code": 200,
        "status": "OK",
        "token": token
    }), 200

@app.route("/api/v1/auth/signup", methods=["POST"])
def signup():
    body = request.get_json()

    # Check the if the user exists
    user = UserModel.query.filter_by(email=body['email']).first()

    if user is not None:
        data = {
            "code": 400,
            "status": "Bad Request",
            "errors": [
                {
                    "error": "Your email is already registered"
                }
            ]
        }

        return jsonify(data), 400

    # Create a new user
    random_api_key = os.urandom(32).hex()
    new_user = UserModel(body['name'], body['email'], body['password'], UserModel.ph.hash(random_api_key))

    db.session.add(new_user)
    db.session.commit()

    data = {
        "code": 201,
        "status": "Created",
        "data": {
            "apiKey": random_api_key
        }
    }

    return jsonify(data), 201

@app.route("/api/v1/auth/me", methods=["GET"])
@token_required
def get_me():
    data = {
        "code": 200,
        "status": "OK",
        "data": request.user
    }

    return jsonify(data), 200

@app.route("/api/v1/api_key", methods=["GET"])
@token_required
def get_api_key():

    # Get the logged in user from prev middleware
    user = request.user

    # Get the user from the database
    user = UserModel.query.filter_by(email=user['email']).first()

    data = {
        "code": 200,
        "status": "OK",
        "data": user.api_key
    }

    return jsonify(data), 200

@app.route("/api/v1/auth/logout", methods=["DELETE"])
@token_required
def logout():
    resp = make_response()
    resp.set_cookie('token', "", httponly=True, expires=0)

    data = {
        "code": 200,
        "status": "OK"
    }

    return jsonify(data), 200

@app.route("/api/v1/model", methods=["POST"])
@token_required
@api_key_required
def run_model():
    # Run your model here

    body = request.get_json()
    input = body['text']

    output = summarize(input)

    if output is None:
        data = {
            "code": 400,
            "status": "Bad Request",
            "errors": [
                {
                    "error": "We can't summarize your text"
                }
            ]
        }

        return jsonify(data), 500

    data = {
        "code": 200,
        "status": "OK",
        "data": {
            "output": output
        }
    }

    return jsonify(data), 200

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(port=int(os.environ.get("PORT")), debug=True, host=os.environ.get("HOST"))