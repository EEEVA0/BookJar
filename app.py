from flask import Flask, render_template, \
    redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Book, Favorite, Comment
from sklearn.preprocessing import MinMaxScaler
import numpy as np
import logging.config
import logging.handlers

logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "simple": {"format": "%(asctime)s - "
                                 "%(name)s - %(levelname)s - "
                                 "%(message)s"}
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "INFO",
                "formatter": "simple",
                "stream": "ext://sys.stdout",
            },
            "error_file_handler": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "ERROR",
                "formatter": "simple",
                "filename": "errors.log",
                "maxBytes": 10485760,
                "backupCount": 20,
                "encoding": "utf8",
            },
            "debug_file_handler": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "INFO",
                "formatter": "simple",
                "filename": "debug.log",
                "maxBytes": 10485760,
                "backupCount": 50,
                "encoding": "utf8",
            },
        },
        "loggers": {
            "my_module": {"level": "ERROR",
                          "handlers": ["console"],
                          "propagate": "no"}
        },
        "root": {
            "level": "INFO",
            "handlers": ["console", "error_file_handler",
                         "debug_file_handler"],
        },
    }
)


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///book.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

logger = logging.getLogger('my_module')

db.init_app(app)

with app.app_context():
    db.create_all()

scaler = MinMaxScaler()


# Home page routing
@app.route('/')
def index():
    # Get all Books
    books = Book.query.all()

    # Group books by category
    books_by_category = {}
    for book in books:
        if book.category not in books_by_category:
            books_by_category[book.category] = []
        books_by_category[book.category].append(book)

    categories = list(books_by_category.keys())

    return render_template('index.html',
                           books_by_category=books_by_category,
                           categories=categories)


# Registered route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        confirm_password = request.form.get('confirm_password').strip()

        # Verify user name and password
        if not username or not password:
            app.logger.error(f"Registration failure: User "
                             f"name or password is empty, "
                             f"user name：{username}")
            flash('The user name and password cannot be empty！', 'error')
            return redirect(url_for('register'))
        if not (3 <= len(username) <= 20):
            app.logger.error(f"Registration failure: "
                             f"The length of the user name does not "
                             f"meet the requirements：{username}")
            flash('The username must be 3 to 20 characters long!', 'error')
            return redirect(url_for('register'))

        if not (6 <= len(password) <= 20):
            app.logger.error(f"Registration failure: "
                             f"The password length does not "
                             f"meet the requirements,"
                             f"username：{username}")
            flash('Password must be 6 to 20 characters long!', 'error')
            return redirect(url_for('register'))
        if password != confirm_password:
            app.logger.warning(f"Registration failure: "
                               f"Password and confirmation password "
                               f"are inconsistent, "
                               f"user name：{username}")
            flash('The password is different from the '
                  'confirmation password！', 'error')
            return redirect(url_for('register'))

        # Check whether the user name already exists
        user = User.query.filter_by(username=username).first()
        if user:
            app.logger.error(f"Registration failure: "
                             f"User name already exists. "
                             f"User name：{username}")
            flash('The user name already exists！', 'error')
            return redirect(url_for('register'))

        # password encryption
        hashed_password = generate_password_hash(
            password, method='pbkdf2:sha256')

        # Create a new user
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        try:
            db.session.commit()
            app.logger.info(f"User registration success, user name：{username}")
            flash('Registered successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration failure, "
                             f"abnormal information：{str(e)}, "
                             f"username：{username}")
            flash(f'fail to register: {str(e)}', 'error')
            return redirect(url_for('register'))

        flash('Registered successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# Entry route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        login_type = request.form.get('login_type')

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('The user name or password is incorrect！', 'error')
            return redirect(url_for('login'))

        session['user_id'] = user.id

        # Check the login type and go to the corresponding page
        if login_type == 'admin':
            if user.is_admin:  # If you are an administrator
                flash('Administrator login succeeded！', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('You do not have administrator rights！', 'error')
                return redirect(url_for('login'))  # Return to login page
        elif login_type == 'user':
            # If you are an administrator, do not log in as a common user
            if user.is_admin:
                flash('The administrator account '
                      'cannot be used to log in as a '
                      'common user！', 'error')
                return redirect(url_for('login'))
            flash('User login successful！', 'success')
            return redirect(url_for('index'))  # Go to the user home page

        else:
            flash('Invalid login type！', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


# Log out route
@app.route('/logout')
def logout():
    session.clear()  # Clears all session data
    flash('You have successfully logged out！', 'success')
    return redirect(url_for('index'))


# Book details routing
@app.route('/book/<int:order>', methods=['GET', 'POST'])
def book_detail(order):
    book = Book.query.filter_by(order=order).first_or_404()

    # Check that the user is logged in and has bookmarked the book
    is_favorite = False
    if 'user_id' in session:
        user_id = session['user_id']
        favorite = Favorite.query.filter_by(
            user_id=user_id, book_order=book.order).first()
        is_favorite = favorite is not None

    return render_template('book_detail.html',
                           book=book, is_favorite=is_favorite)


# Add books to favorites
@app.route('/add_to_favorites/<int:book_order>', methods=['POST'])
def add_to_favorites(book_order):
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in first！', 'error')
        return redirect(url_for('login'))

    # Check if the book is already in the collection
    existing_favorite = Favorite.query.\
        filter_by(user_id=user_id, book_order=book_order).first()
    if existing_favorite:
        flash('The book is already in your favorites！', 'info')
    else:
        # If not, create a new collection
        favorite = Favorite(user_id=user_id, book_order=book_order)
        db.session.add(favorite)
        db.session.commit()
        flash('Books have been added to your favorites！', 'success')

    return redirect(url_for('book_detail', order=book_order))


# The Favorites page displays all of the current user's favorites
@app.route('/favorites')
def favorites():
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in first！', 'error')
        return redirect(url_for('login'))
    favorites = Favorite.query.filter_by(user_id=user_id).all()

    # Get information about books in your collection
    books_in_favorites = [favorite.book for favorite in favorites]

    return render_template('favorite.html', books=books_in_favorites)


# Delete books from your favorites
@app.route('/remove_from_favorites/<int:book_order>', methods=['POST'])
def remove_from_favorites(book_order):
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in first！', 'error')
        return redirect(url_for('login'))

    # Find and delete the user's favorites
    favorite = Favorite.query.filter_by(
        user_id=user_id, book_order=book_order).first()
    if favorite:
        db.session.delete(favorite)
        db.session.commit()
        flash('The book has been removed from your favorites！', 'success')
    else:
        flash('This book is not in your favorites！', 'error')

    return redirect(url_for('favorites'))


# add comment route
@app.route('/book/<int:order>/comment', methods=['POST'])
def add_comment(order):
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in first！', 'error')
        return redirect(url_for('login'))

    # Gets the comment content in the form
    content = request.form.get('content').strip()

    if not content:
        flash('Comments cannot be empty！', 'error')
        return redirect(url_for('book_detail', order=order))

    # Create a new comment
    comment = Comment(content=content, user_id=user_id, book_order=order)
    db.session.add(comment)
    db.session.commit()

    flash('Comment submitted successfully！', 'success')
    return redirect(url_for('book_detail', order=order))


def normalize_features(books):
    prices = np.array([book.price for book in books]).reshape(-1, 1)
    years = np.array([book.year for book in books]).reshape(-1, 1)

    # Normalized prices and years
    prices_normalized = scaler.fit_transform(prices)
    years_normalized = scaler.fit_transform(years)

    return prices_normalized, years_normalized


# Weighted cosine similarity
def weighted_cosine_similarity(book1, book2,
                               weight_year=0.25,
                               weight_price=0.25,
                               weight_category=0.25,
                               weight_author=0.25):
    # Normalized prices and years
    prices_normalized, years_normalized = normalize_features([book1, book2])

    # eigenvector
    year_diff = years_normalized[0] - years_normalized[1]
    price_diff = prices_normalized[0] - prices_normalized[1]

    # Class similarity (1 if identical, 0 otherwise)
    category_similarity = 1 if book1.category == book2.category else 0

    # Author similarity (1 if identical, 0 otherwise)
    author_similarity = 1 if book1.author == book2.author else 0

    # Calculate the weighted cosine similarity
    year_similarity = 1 / (1 + abs(year_diff))
    price_similarity = 1 / (1 + abs(price_diff))

    similarity_score = (weight_year * year_similarity +
                        weight_price * price_similarity +
                        weight_category * category_similarity +
                        weight_author * author_similarity)

    return similarity_score


# Recommend books for current users
def recommend_books(user_id, books, top_n=10):
    user_books = Favorite.query.filter_by(user_id=user_id).all()
    user_books = [favorite.book for favorite in user_books]

    recommendations = []

    for book in books:
        if book in user_books:
            continue  # Exclude books that the user already owns

        total_similarity = 0
        for user_book in user_books:
            total_similarity += weighted_cosine_similarity(user_book, book)

        recommendations.append((book, total_similarity))

    # Return the top top_n recommended books, sorted by similarity
    recommendations = sorted(recommendations, key=lambda x: x[1], reverse=True)

    return [book for book, _ in recommendations[:top_n]]


# recommendations route
@app.route('/recommendations')
def recommendations():
    # Get the currently logged in user
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in first！', 'error')
        return redirect(url_for('login'))

    # Get all Books
    books = Book.query.all()

    # Invoke the recommendation algorithm to recommend books to the user
    recommended_books = recommend_books(user_id, books)

    return render_template('recommend.html', books=recommended_books)


# profile route
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    # Gets the current page number, first page by default
    page = request.args.get('page', 1, type=int)
    per_page = 3

    # Queries comments posted by the current user and paginates them
    pagination = Comment.query.filter_by(user_id=user.id).\
        order_by(Comment.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Get the book information corresponding to the review
    comments_with_books = []
    for comment in pagination.items:
        # Use the book_order foreign key to query the corresponding book
        book = Book.query.filter_by(order=comment.book_order).first()
        comments_with_books.append({
            'comment': comment,
            'book': book
        })

    return render_template(
        'profile.html',
        user=user,
        comments_with_books=comments_with_books,
        pagination=pagination,
        active_tab='comments'
    )


# update_username route
@app.route('/update_username', methods=['GET', 'POST'])
def update_username():

    user = User.query.get(session['user_id'])

    if not user:
        flash('The user does not exist.！', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_username = request.form['new_username']

        # Server-side authentication: The username
        # must be between 3 and 20 characters long
        if len(new_username) < 3 or len(new_username) > 20:
            flash('用户名必须在3到20个字符之间！', 'danger')
            return redirect(url_for('update_username'))

        # Check whether the new user name already exists
        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user:
            flash('Username already exists, please '
                  'select another username!', 'danger')
            return redirect(url_for('update_username'))

        # Update the username and save it to the database
        user.username = new_username
        db.session.commit()

        flash('The user name is updated successfully！', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html')


# update password route
@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    if 'user_id' not in session:
        flash('Please log in first！', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Verify that the current password is correct
        if not check_password_hash(user.password, current_password):
            flash('Current password error！', 'danger')
            return redirect(url_for('update_password'))

        # Verify the new password and verify that the password is the same
        if new_password != confirm_password:
            flash('The new password is different '
                  'from the confirmed password！', 'danger')
            return redirect(url_for('update_password'))

            # Server-side authentication: The new
            # password must be between 6 and 20 characters long
            if len(new_password) < 3 or len(new_password) > 20:
                flash('The new password must be between '
                      '3 and 20 characters long！', 'danger')
                return redirect(url_for('update_password'))

        # Update the password and save it to the database
        user.password = generate_password_hash(new_password)
        db.session.commit()

        flash('Password updated successfully！', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html')


# admin_dashboard route
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    # Check whether the user is an administrator
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in first！', 'error')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash('No permission to access this page！', 'error')
        return redirect(url_for('index'))

    # Process the add books form
    if request.method == 'POST':
        order = request.form.get('order')
        name = request.form.get('name')
        author = request.form.get('author')
        year = request.form.get('year')
        price = request.form.get('price')
        currency = request.form.get('currency')
        category = request.form.get('category')
        img_paths = request.form.get('img_paths')
        description = request.form.get('description')

        # If img_paths is empty or invalid, use the default placeholder
        if not img_paths:
            img_paths = 'img/default.jpg'

        # Create a new book object
        new_book = Book(
            order=order,
            name=name,
            author=author,
            year=year,
            price=price,
            currency=currency,
            category=category,
            img_paths=img_paths,
            description=description
        )

        # Save to database
        db.session.add(new_book)
        db.session.commit()

        flash('Books added successfully！', 'success')
        return redirect(url_for('admin_dashboard'))

    # Gets all categories for drop-down selection
    categories = db.session.query(Book.category).distinct().all()
    categories = [cat[0] for cat in categories]

    books = Book.query.all()
    users = User.query.all()
    comments = Comment.query.all()

    # Statistical magnitude
    num_users = len(users)
    num_books = len(books)
    num_comments = len(comments)
    # The render administrator controls
    # the panel page, passing the list of categories
    return render_template('admin_dashboard.html',
                           categories=categories, books=books,
                           users=users, comments=comments,
                           num_users=num_users,
                           num_books=num_books,
                           num_comments=num_comments)


# delete comment in admin_dashboard route
@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    # Check whether the user is an administrator
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in first！', 'error')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash('No permission to perform this operation！', 'error')
        return redirect(url_for('index'))

    # Find the comment you want to remove
    comment = Comment.query.get(comment_id)
    if not comment:
        flash('Comment does not exist！', 'error')
        return redirect(url_for('admin_dashboard'))

    # Delete Comment
    db.session.delete(comment)
    db.session.commit()

    flash('Comment deleted successfully！', 'success')
    return redirect(url_for('admin_dashboard'))


# delete books in admin_dashboard route
@app.route('/delete_book/<int:book_order>', methods=['POST'])
def delete_book(book_order):
    # Check whether the user is an administrator
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in first！', 'error')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash('No permission to perform this operation！', 'error')
        return redirect(url_for('index'))

    # Find the book you want to delete
    book = Book.query.filter_by(order=book_order).first()
    if not book:
        flash('Books do not exist！', 'error')
        return redirect(url_for('admin_dashboard'))

    # Delete book
    db.session.delete(book)
    db.session.commit()

    flash('Book deletion success！', 'success')
    return redirect(url_for('admin_dashboard'))


# Edit book information
@app.route('/edit_book/<int:book_order>', methods=['GET', 'POST'])
def edit_book(book_order):
    # Check whether the user is an administrator
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in first！', 'error')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash('No permission to perform this operation！', 'error')
        return redirect(url_for('index'))

    # Find the book to edit
    book = Book.query.filter_by(order=book_order).first()
    if not book:
        flash('Books do not exist.！', 'error')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        # Update book information
        book.name = request.form.get('name')
        book.author = request.form.get('author')
        book.year = request.form.get('year')
        book.price = request.form.get('price')
        book.currency = request.form.get('currency')
        book.category = request.form.get('category')
        book.img_paths = request.form.get('img_paths') or 'img/default.jpg'
        book.description = request.form.get('description')

        db.session.commit()

        flash('The book information is updated successfully！', 'success')
        return redirect(url_for('admin_dashboard'))

    # Gets all categories for drop-down selection
    categories = db.session.query(Book.category).distinct().all()
    categories = [cat[0] for cat in categories]

    # Render edit page
    return render_template('edit_book.html', book=book, categories=categories)


# View book details
@app.route('/view_book/<int:book_order>', methods=['GET'])
def view_book(book_order):
    # Check whether the user is an administrator
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in first！', 'error')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash('No permission to perform this operation！', 'error')
        return redirect(url_for('index'))

    # Find the book you want to view
    book = Book.query.filter_by(order=book_order).first()
    if not book:
        flash('Books do not exist.！', 'error')
        return redirect(url_for('admin_dashboard'))

    # Render View the book details page
    return render_template('view_book.html', book=book)


# The route of the user is deleted
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # Get user object
    user = User.query.get(user_id)

    if user:
        try:
            db.session.delete(user)
            db.session.commit()
            flash('The user is deleted successfully！', 'success')
        except Exception as e:
            db.session.rollback()
            print(f"Error deleting user: {e}")
            flash('Error deleting user, please try again later!', 'error')

    return redirect(url_for('admin_dashboard'))


# If you want to provide a separate logout route for administrators
@app.route('/admin_logout')
def admin_logout():
    session.pop('user_id', None)  # Example Delete a user ID from the session
    flash('The administrator has logged out.！', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        try:
            # Only missing tables are created,
            # and existing tables are not deleted
            db.create_all()
            app.logger.info("The database table "
                            "is created successfully. Procedure")

            # Import the pandas library to handle CSV files
            import pandas as pd

            df = pd.read_csv('books.csv', encoding='GBK')

            # Insert CSV data into the database line by line
            for idx, row in df.iterrows():
                # Check if there are already books with the same order
                existing_book = Book.query.\
                    filter_by(order=row['order']).first()
                if existing_book:
                    # If the book.order already exists, skip the insertion
                    continue

                # If there is no duplicate order, insert a new book
                book = Book(
                    order=row['order'],
                    name=row['name'],
                    author=row['author'],
                    year=row['year'],
                    price=float(row['price']),
                    currency=row['currency'],
                    category=row['category'],
                    img_paths=row['img_paths'],
                    description=row['description']
                )

                try:
                    db.session.add(book)
                    app.logger.info(f"Successfully add books："
                                    f"{row['name']}，"
                                    f"Order number：{row['order']}")
                except Exception as e:
                    db.session.rollback()  # If adding books fails, roll back
                    app.logger.error(f"Failed to add books. An exception "
                                     f"message is displayed：{str(e)}，"
                                     f"books：{row['name']}，"
                                     f"order number：{row['order']}")

            # Commit to database
            try:
                db.session.commit()
                # System operation success logs
                app.logger.info("All books were successfully "
                                "submitted to the database")
            except Exception as e:
                db.session.rollback()  # If the submission fails, roll back
                app.logger.error(f"Failed to submit the book "
                                 f"data to the database：{str(e)}")

        except Exception as e:
            app.logger.error(f"System error: Database operation failed "
                             f"and abnormal information is displayed：{str(e)}")

        app.run(debug=True)
