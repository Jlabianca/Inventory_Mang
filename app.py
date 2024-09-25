from flask import Flask, render_template, redirect, url_for, request, session, flash
from models import db, User, Product, Transaction
from forms import LoginForm, SignUpForm, AddProductForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with your own secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database and migration
db.init_app(app)
migrate = Migrate(app, db)

def create_admin():
    with app.app_context():
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                password=generate_password_hash('admin123', method='pbkdf2:sha256'),
                name='Administrator',
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully.")

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('inventory'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            message = "Username is already taken, please try again."
            return render_template('index.html', message=message, success=False)
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            name=form.name.data,
            is_admin=False
        )
        db.session.add(new_user)
        db.session.commit()
        message = "Sign up successful."
        return render_template('index.html', message=message, success=True)
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            # Set session variables
            session['logged_in'] = True
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['is_admin'] = user.is_admin
            # Redirect to inventory page
            return redirect(url_for('inventory'))
        else:
            message = "Invalid username or password."
            return render_template('login.html', form=form, message=message)
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/inventory')
def inventory():
    if 'logged_in' in session:
        products = Product.query.filter_by(deleted=False).all()
        return render_template('inventory.html', products=products, user_name=session['user_name'], is_admin=session.get('is_admin', False))
    return redirect(url_for('login'))

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    form = AddProductForm()
    if form.validate_on_submit():
        product = Product(name=form.name.data, quantity=form.quantity.data)
        db.session.add(product)
        db.session.commit()
        # Log the transaction
        transaction = Transaction(
            product_id=product.id,
            user_id=session['user_id'],
            quantity=product.quantity,
            action='Added',
            timestamp=datetime.now()
        )
        db.session.add(transaction)
        db.session.commit()
        flash('Product added successfully.', 'success')
        return redirect(url_for('inventory'))
    return render_template('add_product.html', form=form)

@app.route('/update_product/<int:product_id>', methods=['GET', 'POST'])
def update_product(product_id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    product = Product.query.filter_by(id=product_id, deleted=False).first()
    if not product:
        flash('Product not found or has been deleted.', 'danger')
        return redirect(url_for('inventory'))
    form = AddProductForm(obj=product)
    if form.validate_on_submit():
        old_quantity = product.quantity
        product.name = form.name.data
        product.quantity = form.quantity.data
        db.session.commit()
        # Log the transaction
        transaction = Transaction(
            product_id=product.id,
            user_id=session['user_id'],
            quantity=product.quantity - old_quantity,
            action='Updated',
            timestamp=datetime.now()
        )
        db.session.add(transaction)
        db.session.commit()
        flash('Product updated successfully.', 'success')
        return redirect(url_for('inventory'))
    return render_template('add_product.html', form=form)

@app.route('/delete_product/<int:product_id>')
def delete_product(product_id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    product = Product.query.get_or_404(product_id)
    # Perform soft delete
    product.deleted = True
    db.session.commit()
    # Log the transaction
    transaction = Transaction(
        product_id=product.id,
        user_id=session['user_id'],
        quantity=product.quantity,
        action='Deleted',
        timestamp=datetime.now()
    )
    db.session.add(transaction)
    db.session.commit()
    flash('Product deleted successfully.', 'success')
    return redirect(url_for('inventory'))

@app.route('/history')
def user_history():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    transactions = Transaction.query.filter_by(user_id=session['user_id']).order_by(Transaction.timestamp.desc()).all()
    return render_template('history.html', transactions=transactions, is_admin=False)

@app.route('/admin_history')
def admin_history():
    if 'logged_in' not in session or not session.get('is_admin', False):
        return redirect(url_for('inventory'))
    transactions = Transaction.query.order_by(Transaction.timestamp.desc()).all()
    return render_template('history.html', transactions=transactions, is_admin=True)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    from forms import UpdateProfileForm
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    form = UpdateProfileForm(obj=user)
    if form.validate_on_submit():
        # Check if username is being changed and if it's unique
        if form.username.data != user.username:
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash('Username already taken. Please choose another one.', 'danger')
                return render_template('profile.html', form=form)
        user.name = form.name.data
        user.username = form.username.data
        # Update password if provided
        if form.password.data:
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        # Update session variables if username or name changed
        session['user_name'] = user.name
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()
    app.run(debug=True)
