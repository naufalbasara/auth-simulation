import os

from flask import Flask
from flask_jwt_extended import JWTManager

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev'
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    jwt_app_secret = os.environ.get('JWT_SECRET')
    app.config['JWT_SECRET_KEY'] = jwt_app_secret

    jwt = JWTManager()
    jwt.init_app(app=app)

    from . import db
    db.init_app(app)
    register_blueprints(app)

    return app

def register_blueprints(app):
    from .api.v1.app import bp as v1bp
    from .api.v2.app import bp as v2bp
    
    app.register_blueprint(v1bp)
    app.register_blueprint(v2bp)