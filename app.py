from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET_KEY"
bcrypt = Bcrypt(app)

# Weak temporary user database (intentionally insecure)
users = {}


# ============================
# HOME ROUTE
# ============================
@app.route('/')
def home():
    if "username" in session:
        return redirect('/dashboard')
    return render_template('login.html')


# ============================
# INSECURE LOGIN (weak auth / SQLi-style logic)
# ============================
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Insecure: any registered user can log in if they know the weak password "123"
    if username in users and password == "123":
        session['username'] = username
        return redirect('/dashboard')

    return "Invalid login"


# ============================
# REGISTRATION (still insecure demo)
# ============================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        users[username] = hashed_pw

        return redirect('/')

    return render_template('register.html')


# ============================
# INSECURE DASHBOARD (XSS vulnerability)
# ============================
@app.route('/dashboard')
def dashboard():
    if "username" not in session:
        return redirect('/')

    # Insecure: user input is rendered directly (XSS)
    user_note = request.args.get("note", "")

    return render_template(
        'dashboard.html',
        user=session["username"],
        user_note=user_note
    )


# ============================
# RUN APP
# ============================
if __name__ == "__main__":
    app.run(debug=True)
