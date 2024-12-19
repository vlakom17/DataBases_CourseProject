from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_cors import CORS

from . database import db 

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    

    CORS(app)  # Разрешить все запросы с любых доменов
    db.init_app(app)

    with app.app_context():
        # Создание таблиц, если их еще нет
        db.create_all()
        from . import routes, models  # Регистрация маршрутов и моделей

        # Регистрация Blueprint
        from .routes import auth_bp, usr_bp, list_bp, pr_bp, rvi_bp, init_bp  # Импортируем Blueprint
        app.register_blueprint(init_bp)  # Регистрируем Blueprint в приложении
        app.register_blueprint(auth_bp)
        app.register_blueprint(usr_bp)
        app.register_blueprint(list_bp)
        app.register_blueprint(pr_bp)
        app.register_blueprint(rvi_bp)
        # Печать маршрутов
        print("Registered routes:")
        print(app.url_map)
    return app



