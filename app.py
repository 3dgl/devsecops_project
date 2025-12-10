from flask import Flask, render_template, request, redirect, session
import sqlite3

app = Flask(__name__)
app.secret_key = "devsecops123"

# ---------------------------
# DATABASE CONNECTION
# ---------------------------
def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

# ---------------------------
# HOME -> REDIRECT TO LOGIN
# ---------------------------
@app.route("/")
def home():
    return redirect("/login")

# ---------------------------
# REGISTER (SAFE ENOUGH)
# ---------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("INSERT INTO users (username, password, note) VALUES (?, ?, '')", (username, password))
        conn.commit()
        return redirect("/login")

    return render_template("register.html")

# ---------------------------
# LOGIN (INSECURE – SQL INJECTION)
# ---------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()

        # 🔥 UNSAFE SQL – vulnerable to SQL Injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print("Executing:", query)  # يظهر بالترمينال لإثبات الثغرة
        cursor.execute(query)

        user = cursor.fetchone()

        if user:
            session["user"] = user["username"]
            return redirect("/dashboard")
        else:
            return "Invalid login"

    return render_template("login.html")

# ---------------------------
# DASHBOARD
# ---------------------------
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" not in session:
        return redirect("/login")

    username = session["user"]

    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":
        note = request.form["note"]
        cursor.execute("UPDATE users SET note = ? WHERE username = ?", (note, username))
        conn.commit()

    cursor.execute("SELECT note FROM users WHERE username = ?", (username,))
    note = cursor.fetchone()["note"]

    return render_template("dashboard.html", user=username, user_note=note)

# ---------------------------
# LOGOUT
# ---------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------------------------
# RUN APP
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)
