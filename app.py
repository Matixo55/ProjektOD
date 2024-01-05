import base64
import io
import os
import random
import re
import sqlite3
import time
from datetime import datetime

import pyotp
import qrcode
from flask_talisman import Talisman
import bleach
import markdown
from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from passlib.hash import sha256_crypt
from flask_wtf.csrf import CSRFProtect
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64decode, b64encode
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
csrf = CSRFProtect(app)
app.config["SECRET_KEY"] = "c05c0128856ec80ca6f7b9ae827d0acad406182bcf14d0670ea83d5e46d67151"
app.config[
    "WTF_CSRF_SECRET_KEY"
] = "b042653a869da49f9e6292fdae0b97559d5a4bb5e894047b2bceeed0e1636845"
# Konfiguracja Content-Security-Policy
csp = {
    "default-src": "'self'",
    "script-src": ["'self'", "https://cdnjs.cloudflare.com"],
    "style-src": ["'self'", "https://stackpath.bootstrapcdn.com", "https://cdnjs.cloudflare.com"],
    "font-src": ["'self'", "https://stackpath.bootstrapcdn.com", "https://cdnjs.cloudflare.com"],
    "img-src": "'self'",
}

Talisman(app, content_security_policy=csp)

login_manager = LoginManager(app)
special_characters = re.compile("[@_!#$%^&*()<>?/\|}{~:]")

DATABASE = "./sqlite3.db"

LOGIN_ATTEMPTS_DELAY = {
    1: 3,
    2: 10,
    3: 60,
    4: 300,
    5: 600,
}
allowed_tags = ["p", "a", "strong", "em", "h1", "h2", "h3", "img"]
allowed_attributes = {"a": ["href", "title"], "img": ["src", "alt"]}


def init_db():
    print("[*] Init database!")
    with sqlite3.connect(DATABASE) as db:
        sql = db.cursor()
        sql.execute("DROP TABLE IF EXISTS user;")
        sql.execute(
            "CREATE TABLE user (username VARCHAR(32) NOT NULL,email VARCHAR(128), password VARCHAR(128) NOT NULL,salt VARCHAR(16) NOT NULL, totp VARCHAR(40) NOT NULL, login_attempts INT DEFAULT 0, last_attempt TIMESTAMP);"
        )
        sql.execute("DROP TABLE IF EXISTS notes;")
        sql.execute(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32) not null, note VARCHAR(512), encrypted BIT, salt VARCHAR(16), iv VARCHAR(16));"
        )
        sql.execute("DROP TABLE IF EXISTS note_share")
        sql.execute(
            "CREATE TABLE note_share (id INTEGER PRIMARY KEY, note_id INTEGER not null, recipient_username VARCHAR(32));"
        )
        sql.execute("DROP TABLE IF EXISTS activity_log")
        sql.execute(
            "CREATE TABLE activity_log (id INTEGER PRIMARY KEY, username VARCHAR(32), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, ip VARCHAR(32), user_agent VARCHAR(256));"
        )

        # Password1234)
        sql.execute(
            f"INSERT INTO user (username, password, salt, totp, email) VALUES ('steve', '$5$rounds=535000$u1dEwt7ffnDsfO6M$EQrQidi1AsUxbOMGWSA5515/S0bSvXcDwc1FHcB0/1D', 'b1fd56a0b1a3ea03','{pyotp.random_base32()}', 'steve@gmail.com');"
        )
        db.commit()


def create_app():
    init_db()
    return app


class HttpStatus:
    OK = 200
    NOT_FOUND = 404
    FORBIDDEN = 403
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    REDIRECT = 303
    TOO_MANY_REQUESTS = 429


# Wyłączenie nagłówka Server
@app.after_request
def remove_server_header(response):
    response.headers["Server"] = ""
    return response


def encrypt_message(message, password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    ciphertext = base64.urlsafe_b64encode(ciphertext).decode()
    iv = base64.urlsafe_b64encode(iv).decode()

    return ciphertext, iv


def decrypt_message(salt, iv, ciphertext, password):
    iv = urlsafe_b64decode(iv)
    ciphertext = urlsafe_b64decode(ciphertext)
    salt = salt.encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_message.decode()


def is_weak_password(password):
    return (
        len(password) < 12
        or not any(char.isupper() for char in password)
        or not any(char.islower() for char in password)
        or not any(char.isdigit() for char in password)
        or not special_characters.search(password)
    )


def reset_login_attempts(username):
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute(
            "UPDATE user SET login_attempts = 0, last_attempt = NULL WHERE username = ?", [username]
        )
        db.commit()


def update_login_attempts(username):
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute(
            """
                UPDATE user SET 
                login_attempts = CASE WHEN login_attempts < 5 THEN login_attempts + 1 ELSE login_attempts END, 
                last_attempt = CURRENT_TIMESTAMP WHERE username = ?
            """,
            [username],
        )
        db.commit()


def get_login_attempts(username):
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT login_attempts, last_attempt at FROM user WHERE username = ?", [username]
        )
        result = cursor.fetchone()

        return result if result else (None, None)


class User(UserMixin):
    def __init__(self, username, password, salt, totp, email):
        self.id = username
        self.password = password
        self.salt = salt
        self.totp = totp
        self.email = email


@login_manager.user_loader
def user_loader(username):
    with sqlite3.connect(DATABASE) as db:
        sql = db.cursor()
        sql.execute(
            "SELECT username, password, salt, totp, email FROM user WHERE username = ?", [username]
        )
        row = sql.fetchone()

    if row:
        username, password, salt, totp, email = row
        user = User(username, password, salt, totp, email)
        return user

    return None


@login_manager.request_loader
def request_loader(request):
    username = request.form.get("username")
    user = user_loader(username)
    return user


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    if request.method == "POST":
        username = request.form.get("username", None)
        password = request.form.get("password", None)
        email = request.form.get("email", None)

        if not username or not password or not email:
            return "One of the values is empty", HttpStatus.BAD_REQUEST

        if len(username) > 32 or len(password) > 128 or len(email) > 128:
            return "One of the values is too long", HttpStatus.BAD_REQUEST

        with sqlite3.connect(DATABASE) as db:
            con = db.cursor()

            con.execute(f"SELECT EXISTS(SELECT 1 FROM user WHERE email = ?)", [email])
            row = con.fetchone()

            if row[0]:
                return "User already exists.", HttpStatus.BAD_REQUEST
            if is_weak_password(password):
                return render_template(
                    "register.html",
                    username=username,
                    email=email,
                    error_message="Weak password. Please choose a stronger password.",
                )
            salt = secrets.token_hex(8)
            con.execute(
                f"INSERT INTO user (username, password,email, salt, totp) VALUES (?,?,?,?,?)",
                [username, sha256_crypt.hash(salt + password), email, salt, pyotp.random_base32()],
            )
            db.commit()

            user = user_loader(username)
            login_user(user)
            return redirect("/notes", HttpStatus.REDIRECT)


def update_activity_log(ip, user_agent):
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO activity_log (ip, user_agent, username) VALUES (?,?,?)", [ip, user_agent, current_user.id])
        db.commit()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    if request.method == "POST":
        time.sleep(random.random())
        username = request.form.get("username", None)
        password = request.form.get("password", None)
        code = request.form.get("code", None)
        user = user_loader(username)

        if user is None:
            return "Invalid login, password or token", HttpStatus.UNAUTHORIZED

        login_attempts, last_attempt = get_login_attempts(username)

        if last_attempt is not None:
            last_attempt = datetime.strptime(last_attempt, "%Y-%m-%d %H:%M:%S")
            elapsed_time = (datetime.now() - last_attempt).seconds
            if elapsed_time < LOGIN_ATTEMPTS_DELAY[login_attempts]:
                return "Please wait before trying again", HttpStatus.TOO_MANY_REQUESTS

        if sha256_crypt.verify(user.salt + password, user.password) and pyotp.TOTP(
            user.totp
        ).verify(code):
            login_user(user)
            update_activity_log(request.remote_addr, request.user_agent.string)
            return redirect("/notes", HttpStatus.REDIRECT)
        else:
            update_login_attempts(username)
            return "Invalid login, password or token", HttpStatus.UNAUTHORIZED


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "GET":
        return render_template("admin.html")
    if request.method == "POST":
        return "Invalid login or password", HttpStatus.UNAUTHORIZED


@app.route("/notes", methods=["GET"])
@login_required
def notes():
    if request.method == "GET":
        with sqlite3.connect(DATABASE) as db:
            sql = db.cursor()
            sql.execute(f"SELECT id FROM notes WHERE username == ?", [current_user.id])
            notes = sql.fetchall()

        return render_template("notes.html", username=current_user.id, notes=notes)


@app.route("/activity", methods=["GET"])
@login_required
def activity():
    with sqlite3.connect(DATABASE) as db:
        sql = db.cursor()
        sql.execute(f"SELECT created_at, ip, user_agent FROM activity_log WHERE username = ?", [current_user.id])
        activity = sql.fetchall()
    activity_list = [(row[0], row[1], row[2]) for row in activity]
    activity_list = [f"{row[0]} - {row[1]} - {row[2]}" for row in activity_list]

    return render_template("activity.html", activity_list=activity_list)


@app.route("/2fa/", methods=["GET"])
@login_required
def twofa():
    totp = pyotp.TOTP(current_user.totp).provisioning_uri(
        current_user.email, issuer_name="NotesApp"
    )
    qr = qrcode.QRCode(
        version=3, box_size=20, border=10, error_correction=qrcode.constants.ERROR_CORRECT_H
    )
    qr.add_data(totp)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    img_buffer = io.BytesIO()
    img.save(img_buffer)
    img_buffer.seek(0)

    return send_file(img_buffer, mimetype="image/png", as_attachment=False)


@app.route("/render", methods=["POST"])
@login_required
def render():
    md = request.form.get("markdown", "")
    encrypted = request.form.get("encrypted", False)
    password = request.form.get("password", "")
    rendered = markdown.markdown(md)
    salt = None
    iv = None

    cleaned_html = bleach.clean(rendered, tags=allowed_tags, attributes=allowed_attributes)
    if len(cleaned_html) > 256:
        return "Note too long", HttpStatus.BAD_REQUEST
    if len(password) > 128:
        return "Password too long", HttpStatus.BAD_REQUEST

    if encrypted:
        if is_weak_password(password):
            return "Password too weak", HttpStatus.BAD_REQUEST

        salt = secrets.token_hex(8)
        cleaned_html, iv = encrypt_message(cleaned_html, password, salt)
    username = current_user.id
    with sqlite3.connect(DATABASE) as db:
        sql = db.cursor()

        sql.execute(
            f"INSERT INTO notes (username, note, encrypted,salt, iv) VALUES (?,?,?,?,?)",
            [username, cleaned_html, 1 if encrypted else 0, salt, iv],
        )
        db.commit()
        sql.execute(
            f"SELECT id FROM notes WHERE username == ? AND note == ?", [username, cleaned_html]
        )
        rendered_id = sql.fetchone()[0]
    return redirect(f"/render/{rendered_id}", HttpStatus.REDIRECT)


@app.route("/render/<rendered_id>", methods=["GET", "POST"])
@login_required
def render_old(rendered_id):
    decoded = False
    shared = False

    with sqlite3.connect(DATABASE) as db:
        sql = db.cursor()
        sql.execute(f"SELECT username, note, encrypted FROM notes WHERE id == ?", [rendered_id])
        data = sql.fetchone()

        if not data:
            return "Note not found", HttpStatus.NOT_FOUND

        username, rendered, encrypted = data

        if username != current_user.id:
            sql.execute(
                f"SELECT recipient_username FROM note_share WHERE note_id == ?", [rendered_id]
            )
            recipients = sql.fetchall()

            if not recipients or current_user.id not in [recipient[0] for recipient in recipients]:
                return "Access to note forbidden", HttpStatus.FORBIDDEN

            shared = True

        if request.method == "POST":
            password = request.form.get("password", "")
            if not encrypted:
                return "Note not encrypted", HttpStatus.BAD_REQUEST

            sql.execute(f"SELECT note, salt, iv FROM notes WHERE id == ?", [rendered_id])
            note, salt, iv = sql.fetchone()

            rendered = decrypt_message(salt, iv, note, password)
            encrypted = False
            decoded = True

        return render_template(
            "markdown.html",
            rendered=rendered,
            rendered_id=rendered_id,
            encrypted=encrypted,
            decoded=decoded,
            shared=shared,
        )


@app.route("/share/<note_id>", methods=["POST"])
@login_required
def share(note_id):
    user = request.form.get("user", "")

    with sqlite3.connect(DATABASE) as db:
        sql = db.cursor()
        sql.execute(
            f"SELECT encrypted FROM notes WHERE username == ? and id=?", [current_user.id, note_id]
        )
        data = sql.fetchone()
        if not data:
            return "Note not found", HttpStatus.NOT_FOUND
        encrypted = data[0]
        if encrypted:
            return "Note is encrypted", HttpStatus.BAD_REQUEST

        sql.execute(
            "INSERT INTO note_share (note_id, recipient_username) VALUES (?,?)", [note_id, user]
        )
        db.commit()

    return (
        f"Note made available to {user}\n" + url_for("render") + f"/{note_id}",
        HttpStatus.OK,
    )


if __name__ == "__main__":
    app = create_app()
    app.run("0.0.0.0", 5000)
