import os
from flask import Flask, request
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager


app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
# ENV = 'dev'
ENV = 'prod'
# secret key protects against modifying cookies, cross-site requests forgery atttacks etc.
app.config['SECRET_KEY'] = '15363711818daf0f83459c25f7017a90'

if ENV == 'dev':
    app.debug = True
    #  connect to db
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    # 
    # app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
else:
    app.debug = False

    # heruku
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://u8cfl2g3qfs8kq:pdde98a7b527475b9496df5f71a1b1d6997b37ad68c7c65d9177fa085da046b3a@c8lj070d5ubs83.cluster-czrs8kj4isg7.us-east-1.rds.amazonaws.com:5432/d6c7ebcbhbfj1q'
    # local
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:12king34pin@localhost/budget_db'
    
    # Render
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://budge_files_user:L0lVBVhg8uTzNj1lVSQwr1KGvdOrfJ3a@dpg-cpled0ud3nmc73cv7420-a.oregon-postgres.render.com/budge_files'

    # render 2
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://budget_files_postgresql_user:cMpSkry294QvkqnSePihpwYCfKI8fcIY@dpg-cqah0vbv2p9s73d18lv0-a.oregon-postgres.render.com/budget_files_postgresql'

    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URI")


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# create db object
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'



from app import routes