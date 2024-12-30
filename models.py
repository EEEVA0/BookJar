from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    comments = db.relationship('Comment', backref='author', lazy=True)
    is_admin = db.Column(db.Boolean, default=False)


# book model
class Book(db.Model):
    order = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    author = db.Column(db.String(100), nullable=True)
    year = db.Column(db.String(100), nullable=True)
    price = db.Column(db.String(100), nullable=True)
    currency = db.Column(db.String(100), nullable=True)
    category = db.Column(db.String(100), nullable=True)
    img_paths = db.Column(db.String(200), nullable=True)
    description = db.Column(db.String(250), nullable=True)


class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_order = db.Column(db.Integer, db.ForeignKey('book.order'),
                           nullable=False)

    # build relationships
    user = db.relationship('User', backref=db.backref('favorites', lazy=True))
    book = db.relationship('Book', backref=db.backref('favorites', lazy=True))


# Review model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_order = db.Column(db.Integer, db.ForeignKey('book.order'),
                           nullable=False)
    user = db.relationship('User', backref=db.backref('user_comments',
                                                      lazy=True))
    book = db.relationship('Book', backref=db.backref('book_comments',
                                                      lazy=True))
