from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"

DB = "users.db"


# -------------------------
# Database initialization
# -------------------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            content TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()


# -------------------------
# Register
# -------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                  (username, hashed_pw))
        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


# -------------------------
# Login (Protected against SQL Injection)
# -------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if row and bcrypt.checkpw(password.encode(), row[0]):
            session["username"] = username
            return redirect("/dashboard")

        return "Invalid login"

    return render_template("login.html")


# -------------------------
# Dashboard (Protected against XSS)
# -------------------------
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect("/login")

    username = session["username"]

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    if request.method == "POST":
        note = request.form["note"]
        c.execute("INSERT INTO notes (username, content) VALUES (?, ?)",
                  (username, note))
        conn.commit()

    c.execute("SELECT content FROM notes WHERE username = ? ORDER BY id DESC LIMIT 1",
              (username,))
    row = c.fetchone()
    last_note = row[0] if row else ""

    conn.close()

    return render_template("dashboard.html",
                           user=username,
                           last_note=last_note)


# -------------------------
# Logout
# -------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)
