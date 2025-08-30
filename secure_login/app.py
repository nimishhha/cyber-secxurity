from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt, pyotp, os

app = Flask(__name__)
# SECURITY TIP: For real projects, load secret from environment variable instead of hardcoding:
app.secret_key = os.environ.get("FLASK_SECRET", "replace_this_with_env_secret")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

# Home
@app.route('/')
def home():
    return "Welcome! Go to /register or /login"

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        otp_secret = pyotp.random_base32()

        new_user = User(username=username, password=hashed, otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()
        return "User Registered! Now go to /login"
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].encode('utf-8')
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password, user.password):
            session['username'] = username
            session['otp_secret'] = user.otp_secret
            return redirect('/otp')
        else:
            return "Invalid username or password"
    return render_template('login.html')

# OTP Verification
@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if request.method == 'POST':
        otp = request.form['otp'].strip()
        totp = pyotp.TOTP(session['otp_secret'])
        if totp.verify(otp):
            return f"✅ Welcome {session['username']}! Login Successful."
        else:
            return "❌ Invalid OTP"
    return render_template('otp.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
