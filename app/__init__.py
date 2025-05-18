from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_cors import CORS
from .redis_store import init_redis_connection
from . database import db 

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    

    CORS(app)  # Разрешить все запросы с любых доменов
    db.init_app(app)
    app.rdb = init_redis_connection()
    with app.app_context():

        db.create_all()
        from . import routes, models

        from .routes import auth_bp, usr_bp, list_bp, pr_bp, rvi_bp, init_bp
        app.register_blueprint(init_bp)
        app.register_blueprint(auth_bp)
        app.register_blueprint(usr_bp)
        app.register_blueprint(list_bp)
        app.register_blueprint(pr_bp)
        app.register_blueprint(rvi_bp)

    return app



