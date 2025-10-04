from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_socketio import SocketIO, send, emit
from flask_sqlalchemy import SQLAlchemy
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import re
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = "secret123"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///chat.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Gmail SMTP Settings - UPDATE THESE WITH YOUR CREDENTIALS
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "clasherscode6@gmail.com"
EMAIL_PASSWORD = "kknjhlkslpsdkmgl"

# Database Models
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    content = db.Column(db.Text)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(200))

class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=False)
    receiver = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Initialize database
with app.app_context():
    db.create_all()

# Ensure static folder exists
if not os.path.exists('static'):
    os.makedirs('static')

otp_storage = {}
connected_users = {}  # Tracks online users: {username: set(socket_ids)}
password_reset_requests = {}

def is_valid_email(email):
    pattern = r"[^@]+@[^@]+\.[^@]+"
    return re.match(pattern, email)

def is_valid_password(password: str) -> bool:
    if not password or len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    return True

def send_otp_email(to_email, otp, purpose="registration"):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    
    if purpose == "password_reset":
        msg['Subject'] = "CodeClasher - Password Reset Verification Code"
        body_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #ff2a00;">CodeClasher</h1>
                <h3>Password Reset Request</h3>
                <p>Your password reset verification code is:</p>
                <h2 style="color: #4361ee; letter-spacing: 5px; font-size: 2.5rem;">{otp}</h2>
                <p>This code expires in 10 minutes.</p>
                <p style="color: #666; font-size: 0.9rem;">If you didn't request this reset, please ignore this email.</p>
            </div>
        </body>
        </html>
        """
    else:
        msg['Subject'] = "Your CodeClasher Verification Code"
        body_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #ff2a00;">CodeClasher</h1>
                <p>Your verification code is:</p>
                <h2 style="color: #4361ee; letter-spacing: 5px; font-size: 2.5rem;">{otp}</h2>
                <p>This code expires in 5 minutes.</p>
            </div>
        </body>
        </html>
        """
    
    msg.attach(MIMEText(body_html, 'html'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Routes
@app.route("/")
def index():
    return render_template("index.html")

# Static files route
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    step = data.get("step")
    email = data.get("email")
    
    if step == "resend_otp":
        otp = str(random.randint(100000, 999999))
        purpose = otp_storage.get(email, {}).get("purpose", "registration")
        otp_storage[email] = {"otp": otp, "expires": datetime.now() + timedelta(minutes=5), "purpose": purpose}
        return jsonify({"success": send_otp_email(email, otp, purpose)})
    
    elif step == "register":
        username = data.get("username")
        password = data.get("password")
        
        if not username or not email or not password:
            return jsonify({"success": False, "error": "All fields required"})
        
        if User.query.filter_by(email=email).first():
            return jsonify({"success": False, "error": "Email already registered"})
        
        if User.query.filter_by(username=username).first():
            return jsonify({"success": False, "error": "Username already taken"})
        
        if not is_valid_password(password):
            return jsonify({"success": False, "error": "Password must be 8+ chars with uppercase"})
        
        session["reg_data"] = {"username": username, "email": email, "password": password}
        otp = str(random.randint(100000, 999999))
        otp_storage[email] = {"otp": otp, "expires": datetime.now() + timedelta(minutes=5), "purpose": "registration"}
        
        if send_otp_email(email, otp, "registration"):
            return jsonify({"success": True, "next_step": "otp", "email": email})
        return jsonify({"success": False, "error": "Failed to send email"})
    
    elif step == "otp":
        otp = data.get("otp")
        email = session.get("reg_data", {}).get("email")
        otp_entry = otp_storage.get(email)
        
        if otp_entry and otp_entry["otp"] == otp and datetime.now() < otp_entry["expires"]:
            otp_storage.pop(email, None)
            reg_data = session["reg_data"]
            
            user = User(email=reg_data["email"], username=reg_data["username"],
                       password=generate_password_hash(reg_data["password"]))
            db.session.add(user)
            db.session.commit()
            
            session["username"] = reg_data["username"]
            session.pop("reg_data", None)
            return jsonify({"success": True, "next_step": "complete"})
        return jsonify({"success": False, "error": "Invalid OTP"})
    
    elif step == "password":
        password = data.get("password")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session["username"] = user.username
            return jsonify({"success": True, "next_step": "complete"})
        return jsonify({"success": False, "error": "Wrong password"})
    
    elif step == "forgot_password":
        user = User.query.filter_by(email=email).first()
        if user:
            otp = str(random.randint(100000, 999999))
            password_reset_requests[email] = {
                "otp": otp, 
                "expires": datetime.now() + timedelta(minutes=10),
                "user_id": user.id
            }
            if send_otp_email(email, otp, "password_reset"):
                return jsonify({"success": True, "message": "Verification code sent to your email"})
            return jsonify({"success": False, "error": "Failed to send email"})
        return jsonify({"success": False, "error": "Email not found"})
    
    elif step == "reset_password_otp":
        otp = data.get("otp")
        new_password = data.get("new_password")
        reset_request = password_reset_requests.get(email)
        
        if reset_request and reset_request["otp"] == otp and datetime.now() < reset_request["expires"]:
            if not is_valid_password(new_password):
                return jsonify({"success": False, "error": "Password must be 8+ chars with uppercase"})
            
            user = User.query.get(reset_request["user_id"])
            if user:
                user.password = generate_password_hash(new_password)
                db.session.commit()
                password_reset_requests.pop(email, None)
                return jsonify({"success": True, "message": "Password reset successfully"})
        
        return jsonify({"success": False, "error": "Invalid OTP"})
    
    return jsonify({"success": False, "error": "Invalid request"})

@app.route("/chat")
def chat():
    if "username" not in session:
        return redirect(url_for("index"))
    return render_template("chat.html", username=session["username"])

@app.route("/group-chat")
def group_chat():
    if "username" not in session:
        return redirect(url_for("index"))
    return render_template("group-chat.html", username=session["username"])

@app.route("/private-chat")
def private_chat():
    if "username" not in session:
        return redirect(url_for("index"))
    return render_template("private-chat.html", username=session["username"])

@app.route("/get_all_users")
def get_all_users():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    current_user = session["username"]
    all_users = User.query.with_entities(User.username).all()
    user_list = [user[0] for user in all_users if user[0] != current_user]
    
    # Get online users
    online_users = list(connected_users.keys())
    
    return jsonify({
        "all_users": user_list,
        "online_users": online_users
    })

@app.route("/get_private_messages/<other_user>")
def get_private_messages(other_user):
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    current_user = session["username"]
    
    # Get messages between current user and other user
    messages = PrivateMessage.query.filter(
        ((PrivateMessage.sender == current_user) & (PrivateMessage.receiver == other_user)) |
        ((PrivateMessage.sender == other_user) & (PrivateMessage.receiver == current_user))
    ).order_by(PrivateMessage.timestamp.asc()).all()
    
    message_list = []
    for msg in messages:
        message_list.append({
            "sender": msg.sender,
            "receiver": msg.receiver,
            "content": msg.content,
            "timestamp": msg.timestamp.isoformat(),
            "is_sent": msg.sender == current_user
        })
    
    return jsonify({"messages": message_list})
# Add this route to main.py
@app.route("/get_group_chat_users")
def get_group_chat_users():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    current_user = session["username"]
    all_users = User.query.with_entities(User.username).all()
    user_list = [user[0] for user in all_users if user[0] != current_user]
    online_users = list(connected_users.keys())
    
    return jsonify({
        "all_users": user_list,
        "online_users": online_users
    })

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# SocketIO Events
@socketio.on("connect")
def handle_connect():
    print(f"Client connected: {request.sid}")
    if 'username' in session:
        username = session['username']
        if username not in connected_users:
            connected_users[username] = set()
        connected_users[username].add(request.sid)
        
        print(f"User {username} connected. Online users: {list(connected_users.keys())}")
        
        # Broadcast updated user list to all clients
        emit('user_list_update', {
            'online_users': list(connected_users.keys()),
            'action': 'user_online'
        }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    
    # Find which user this socket belongs to
    disconnected_user = None
    for username, sockets in connected_users.items():
        if request.sid in sockets:
            sockets.discard(request.sid)
            if not sockets:
                disconnected_user = username
                connected_users.pop(username, None)
            break
    
    if disconnected_user:
        print(f"User {disconnected_user} disconnected. Online users: {list(connected_users.keys())}")
        
        # Broadcast updated user list to all clients
        emit('user_list_update', {
            'online_users': list(connected_users.keys()),
            'action': 'user_offline'
        }, broadcast=True)

@socketio.on("join_group_chat")
def on_join_group_chat(data):
    username = data.get("username")
    if username:
        print(f"User {username} joined group chat")
        
        # Send chat history
        history = Message.query.order_by(Message.id.desc()).limit(50).all()
        emit("chat_history", [{"username": m.username, "msg": m.content} for m in reversed(history)], to=request.sid)
        
        # Send current online users
        emit("user_list", {
            "online_users": list(connected_users.keys()),
            "all_users": [user[0] for user in User.query.with_entities(User.username).all()]
        }, to=request.sid)

@socketio.on("join_private_chat")
def on_join_private_chat(data):
    username = data.get("username")
    if username:
        print(f"User {username} joined private chat")
        
        # Send current online users for private chat
        all_users = [user[0] for user in User.query.with_entities(User.username).all() if user[0] != username]
        emit("private_chat_users", {
            "online_users": list(connected_users.keys()),
            "all_users": all_users
        }, to=request.sid)

@socketio.on("message")
def handle_message(data):
    username = data.get("username")
    msg = data.get("msg")
    if username and msg:
        message = Message(username=username, content=msg)
        db.session.add(message)
        db.session.commit()
        send({"username": username, "msg": msg}, broadcast=True)

@socketio.on("private_message")
def handle_private_message(data):
    sender = data.get('sender')
    receiver = data.get('receiver')
    msg_text = data.get('msg')
    
    print(f"Private message from {sender} to {receiver}: {msg_text}")
    
    if sender and receiver and msg_text:
        # Save to database (messages to offline users are also saved)
        pm = PrivateMessage(sender=sender, receiver=receiver, content=msg_text)
        db.session.add(pm)
        db.session.commit()
        
        payload = {
            "sender": sender, 
            "receiver": receiver, 
            "msg": msg_text, 
            "timestamp": pm.timestamp.isoformat(),
            "message_id": pm.id
        }
        
        # Send to sender (always)
        if sender in connected_users:
            for sid in connected_users[sender]:
                emit("new_private_message", payload, room=sid)
        
        # Send to receiver if online
        if receiver in connected_users:
            for sid in connected_users[receiver]:
                emit("new_private_message", payload, room=sid)
        
        print(f"Private message saved and delivered. Sender: {sender}, Receiver: {receiver}")

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5001))
    print(f"Starting server on port {port}...")
    socketio.run(app, debug=True, host='127.0.0.1', port=port, allow_unsafe_werkzeug=True)