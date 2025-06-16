from main import app, db

with app.app_context():
    db.create_all()  # This creates the tables in the database based on your models
