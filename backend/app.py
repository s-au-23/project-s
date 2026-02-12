import os
from dotenv import load_dotenv 
load_dotenv() 
import re
from datetime import datetime
from flask import Flask, request, jsonify, render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI
import base64 
import PyPDF2
import io
from flask_cors import CORS
from jinja2 import ChoiceLoader, FileSystemLoader

# --- PATH CONFIGURATION ---
base_dir = os.path.dirname(os.path.abspath(__file__))
backend_templates = os.path.join(base_dir, "templates")
frontend_templates = os.path.abspath(os.path.join(base_dir, "..", "frontend"))

app = Flask(__name__)
CORS(app)

app.jinja_loader = ChoiceLoader([
    FileSystemLoader(backend_templates),
    FileSystemLoader(frontend_templates)
])

# --- DATABASE CONFIGURATION ---
database_url = os.getenv("DATABASE_URL")

if database_url:
  
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
  
    db_path = os.path.join(base_dir, 'lab_reports.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    print(f"⚠️ Using local SQLite at: {db_path}")

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secret-key-123-xyz')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    __tablename__ = 'users_table'  
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users_table.id'))
    summary = db.Column(db.Text)
    score = db.Column(db.Integer)
    date = db.Column(db.String(20))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users_table.id'))
    username = db.Column(db.String(80)) 
    content = db.Column(db.Text)
    date = db.Column(db.String(20))

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users_table.id'))
    username = db.Column(db.String(80))
    message = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(20))

# --- IMPORTANT: CREATE TABLES FOR GUNICORN ---



with app.app_context():
    try:
        db.create_all()
        print("✅ DATABASE TABLES CREATED/VERIFIED!")
    except Exception as e:
        print(f"❌ DATABASE ERROR: {str(e)}")

# --- OPENROUTER SETUP ---
api_key = os.getenv("OPENROUTER_API_KEY")
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=api_key, 
    default_headers={
        "HTTP-Referer": "http://127.0.0.1:5000",
        "X-Title": "Project-G Health AI",
    }
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- ROUTES --- 
@app.route('/chat', methods=['POST'])
@login_required
def chat_ai():
    data = request.json
    user_message = data.get("message")
    if not user_message:
        return jsonify({"reply": "I didn't receive any message."}), 400
    try:
        response = client.chat.completions.create(
            model="google/gemini-2.0-flash-001",
            messages=[
                {"role": "system", "content": "You are a helpful medical assistant for Project-G. Keep answers concise."},
                {"role": "user", "content": user_message}
            ]
        )
        return jsonify({"reply": response.choices[0].message.content})
    except Exception as e:
        print(f"Chat Error: {str(e)}")
        return jsonify({"reply": "Sorry, I am facing some technical issues."}), 500

@app.route('/')
def home():
    name = current_user.username if current_user.is_authenticated else None
    return render_template('index.html', name=name)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if User.query.filter_by(username=data.get('username')).first():
        return jsonify({"error": "User already exists"}), 400
    hashed_password = generate_password_hash(data.get('password'))
    new_user = User(username=data.get('username'), password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registration successful"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password, data.get('password')):
        login_user(user, remember=True)
        return jsonify({"message": "Logged in successfully"}), 200
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/history')
@login_required
def history():
    reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.id.asc()).all()
    return jsonify([{"id": r.id, "score": r.score, "summary": r.summary, "date": r.date} for r in reports])

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    filename = file.filename.lower()
    is_image = filename.endswith(('.png', '.jpg', '.jpeg'))
    is_pdf = filename.endswith('.pdf')
    if not (is_image or is_pdf):
        return jsonify({"error": "Only PDF or Images are allowed"}), 400
    try:
        analysis = ""
        score = 7 
        if is_image:
            image_content = file.read()
            image_base64 = base64.b64encode(image_content).decode('utf-8')
            response = client.chat.completions.create(
                model="google/gemini-2.0-flash-001",
                messages=[{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Analyze medical report. Provide summary and score 1-10."},
                        {"type": "image_url", "image_url": {"url": f"data:{file.content_type};base64,{image_base64}"}}
                    ]
                }]
            )
            analysis = response.choices[0].message.content
        else:
            pdf_reader = PyPDF2.PdfReader(file)
            text_content = "".join([page.extract_text() for page in pdf_reader.pages])
            response = client.chat.completions.create(
                model="google/gemini-2.0-flash-001",
                messages=[
                    {"role": "system", "content": "Analyze medical text. Provide summary and score 1-10."},
                    {"role": "user", "content": text_content}
                ]
            )
            analysis = response.choices[0].message.content

        score_match = re.search(r'Score:\s*(\d+)', analysis, re.IGNORECASE)
        if score_match:
            score = int(score_match.group(1))
        
        new_report = Report(user_id=current_user.id, summary=analysis, score=score, date=datetime.now().strftime("%Y-%m-%d %H:%M"))
        db.session.add(new_report)
        db.session.commit()
        return jsonify({"analysis": analysis, "score": score})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/get-posts')
def get_posts():
    posts = Post.query.order_by(Post.id.desc()).all()
    return jsonify([{"username": p.username, "content": p.content, "date": p.date} for p in posts])

@app.route('/create-post', methods=['POST'])
@login_required
def create_post():
    data = request.json
    new_post = Post(user_id=current_user.id, username=current_user.username, content=data.get('content'), date=datetime.now().strftime("%d %b, %H:%M"))
    db.session.add(new_post)
    db.session.commit()
    return jsonify({"message": "Posted!"})

@app.route('/logout')
def logout():
    logout_user()
    return jsonify({"message": "Logged out"}), 200

# --- ADMIN ROUTES ---
@app.route('/my-secret-dashboard-237')
@login_required
def admin_panel():
    if current_user.username.lower().strip() == 'admin':
        return render_template('admin.html')
    return "<h1>Access Denied</h1>", 403

@app.route('/api/admin/stats', methods=['GET'])
@login_required
def get_admin_stats():
    if current_user.username.lower().strip() != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify({
        "total_users": User.query.count(),
        "total_reports": Report.query.count(),
        "total_posts": Post.query.count(),
        "total_feedbacks": Feedback.query.count(),
        "users": [{"id": u.id, "username": u.username} for u in User.query.all()]
    }), 200

@app.route('/api/send-feedback', methods=['POST'])
@login_required
def send_feedback():
    data = request.json
    new_fb = Feedback(user_id=current_user.id, username=current_user.username, message=data.get('message'), date=datetime.now().strftime("%d %b, %H:%M"))
    db.session.add(new_fb)
    db.session.commit()
    return jsonify({"message": "Feedback received!"})

# --- START APP ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
        print("🚀 Database Tables Created!")
        port_str = os.environ.get("PORT", "5000")
        port = int(port_str) 
    
    app.run(host='0.0.0.0', port=port)