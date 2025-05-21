from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()

def create_app(config=None):
    app = Flask(__name__)
    
    if config:
        app.config.from_object(config)
    else:
        app.config.from_object('app.config.Config')
    
    db.init_app(app)
    migrate.init_app(app, db)
    CORS(app)
    
    from app.routes.auth import auth_bp
    # from app.routes.files import files_bp
    # from app.routes.shares import shares_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    # app.register_blueprint(files_bp, url_prefix='/api/files')
    # app.register_blueprint(shares_bp, url_prefix='/api/shares')
    
    return app
