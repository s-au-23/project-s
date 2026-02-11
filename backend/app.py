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

# SETTING UP MULTIPLE TEMPLATE LOCATIONS
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(backend_templates),
    FileSystemLoader(frontend_templates)
])

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lab_reports.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- OPENROUTER SETUP ---
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY"), 
    default_headers={
        "HTTP-Referer": "http://localhost:5000",
        "X-Title": "Project-G Health AI",
    }
)

# --- LOGIN MANAGER ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    summary = db.Column(db.Text)
    score = db.Column(db.Integer)
    date = db.Column(db.String(20))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    username = db.Column(db.String(80)) 
    content = db.Column(db.Text)
    date = db.Column(db.String(20))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- CORE USER ROUTES ---

@app.route('/')
def home():
    """Renders main dashboard."""
    name = current_user.username if current_user.is_authenticated else None
    return render_template('index.html', name=name)

@app.route('/register', methods=['POST'])
def register():
    """Handles new user registration."""
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
    """Handles user login."""
    data = request.json
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password, data.get('password')):
        login_user(user, remember=True)
        return jsonify({"message": "Logged in successfully"}), 200
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/history')
@login_required
def history():
    """English Comment: Fetch history and health trends for the logged-in user."""
    reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.id.asc()).all()
    return jsonify([{
        "id": r.id, 
        "score": r.score, 
        "summary": r.summary, 
        "date": r.date
    } for r in reports])

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    """AI Medical Report analysis logic."""
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

        score_match = re.search(r'Score:\s*(\d+)', analysis)
        if score_match:
            score = int(score_match.group(1))
        
        new_report = Report(
            user_id=current_user.id,
            summary=analysis,
            score=score,
            date=datetime.now().strftime("%Y-%m-%d %H:%M")
        )
        db.session.add(new_report)
        db.session.commit()
        return jsonify({"analysis": analysis, "score": score})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get-posts')
def get_posts():
    """Get community posts."""
    posts = Post.query.order_by(Post.id.desc()).all()
    return jsonify([{"username": p.username, "content": p.content, "date": p.date} for p in posts])

@app.route('/create-post', methods=['POST'])
@login_required
def create_post():
    """Create new community post."""
    data = request.json
    new_post = Post(
        user_id=current_user.id,
        username=current_user.username,
        content=data.get('content'),
        date=datetime.now().strftime("%d %b, %H:%M")
    )
    db.session.add(new_post)
    db.session.commit()
    return jsonify({"message": "Posted!"})

@app.route('/logout')
def logout():
    """Clear user session."""
    logout_user()
    return jsonify({"message": "Logged out"}), 200

# --- ADMIN ROUTES ---

@app.route('/my-secret-dashboard-237')
@login_required
def admin_panel():
    """English Comment: Show admin dashboard only for 'admin' user."""
    if current_user.username.lower().strip() == 'admin':
        return render_template('admin.html')
    else:
        return f"<h1>Access Denied</h1><p>You are logged in as '{current_user.username}'. Please login as 'admin'.</p>", 403

@app.route('/api/admin/stats', methods=['GET'])
@login_required
def get_admin_stats():
    """English Comment: Fetches global stats for the admin panel."""
    if current_user.username.lower().strip() != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    
    data = {
        "total_users": User.query.count(),
        "total_reports": Report.query.count(),
        "total_posts": Post.query.count(),
        "users": [{"id": u.id, "username": u.username} for u in User.query.all()]
    }
    return jsonify(data), 200

@app.route('/api/admin/posts', methods=['GET'])
@login_required
def get_admin_posts():
    """English Comment: Admin moderation view for all posts."""
    if current_user.username.lower().strip() != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    posts = Post.query.order_by(Post.id.desc()).all()
    return jsonify([{"id": p.id, "username": p.username, "content": p.content, "date": p.date} for p in posts])

@app.route('/api/admin/delete-post/<int:post_id>', methods=['DELETE'])
@login_required
def delete_post_admin(post_id):
    """English Comment: Allows admin to remove any post."""
    if current_user.username.lower().strip() != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    post = Post.query.get(post_id)
    if post:
        db.session.delete(post)
        db.session.commit()
        return jsonify({"success": True}), 200
    return jsonify({"error": "Not found"}), 404

@app.route('/api/admin/user-reports/<int:user_id>', methods=['GET'])
@login_required
def get_user_reports_admin(user_id):
    """English Comment: Admin view of a specific user's health history."""
    if current_user.username.lower().strip() != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    reports = Report.query.filter_by(user_id=user_id).order_by(Report.id.desc()).all()
    return jsonify([{
        "id": r.id, 
        "score": r.score, 
        "summary": r.summary, 
        "date": r.date
    } for r in reports])

# --- START SERVER ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)