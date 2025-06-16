from datetime import datetime
from flask_sqlalchemy import SQLAlchemy  # type: ignore
from flask_login import UserMixin  # type: ignore

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"User('{self.username}', '{self.date_created}')"

# Model for tracking user activity
class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=True)  # New column to store file path
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"UserActivity('{self.username}', '{self.action}', '{self.timestamp}')"

# History model for tracking user activity with file download info
class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=True)  # New column to store file path

    def __repr__(self):
        return f"<History {self.username} performed {self.action} on {self.date}>"
