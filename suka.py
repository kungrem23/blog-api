from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import bcrypt


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = (f'postgresql://{os.getenv("POSTGRES_USERNAME")}:{os.getenv("POSTGRES_PASSWORD")}'
                                         f'@{os.getenv("POSTGRES_HOST")}:{os.getenv("POSTGRES_PORT")}/'
                                         f'{os.getenv("POSTGRES_DATABASE")}')
# db = SQLAlchemy(app)
# migrate = Migrate(app, db)
app.config['SECRET_KEY'] = 'cb781c9c825e4531b89df11ea0eb66ca'
salt = bcrypt.gensalt()
