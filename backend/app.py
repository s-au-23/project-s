import os
import re
from datetime import datetime
from flask import Flask, request, jsonify, render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI
import PyPDF2

# Fix: Use dynamic path to locate the frontend folder relative to this script
base_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(base_dir, "..", "frontend")

app = Flask(__name__, template_folder=template_dir)

# Configuration
app.config['SECRET_KEY'] = 'health_ai_openrouter_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lab_reports.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# OpenRouter Setup
# Redirects standard OpenAI calls to OpenRouter's infrastructure
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key="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",
    default_headers={
        "HTTP-Referer": "http://localhost:5000", # Required by some OpenRouter models
        "X-Title": "Project-G Health AI",        # Your App Name for OpenRouter rankings
    }
)

# Login Manager Initialization
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

# Database Models
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

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- ROUTES ---

@app.route('/')
def home():
    # Pass authenticated username to the template
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

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if not file: 
        return jsonify({"error": "No file uploaded"}), 400
    
    try:
        # Extract Text from the uploaded PDF
        reader = PyPDF2.PdfReader(file)
        text = "".join([p.extract_text() for p in reader.pages if p.extract_text()])
        
        # OpenRouter API Call using Gemini model
        response = client.chat.completions.create(
            model="google/gemini-2.0-flash-001",
            messages=[
                {"role": "user", "content": f"Analyze this lab report. Provide a SCORE: X/10 and a detailed summary. Text: {text}"}
            ]
        )
        
        ai_text = response.choices[0].message.content
        
        # Parse the score using Regex (looks for 'SCORE: 8' format)
        score_match = re.search(r"SCORE:\s*(\d+)", ai_text)
        score = int(score_match.group(1)) if score_match else 5
        
        # Save analysis to the database
        report = Report(
            user_id=current_user.id, 
            summary=ai_text, 
            score=score, 
            date=datetime.now().strftime("%Y-%m-%d")
        )
        db.session.add(report)
        db.session.commit()
        
        return jsonify({"analysis": ai_text, "score": score})
    except Exception as e:
        print(f"API or System ERROR: {e}")
        return jsonify({"error": "Analysis failed. Please check API credits or file format."}), 500

@app.route('/history')
@login_required
def history():
    # Fetch all reports belonging to the current user
    reports = Report.query.filter_by(user_id=current_user.id).all()
    return jsonify([{"score": r.score, "summary": r.summary, "date": r.date} for r in reports])

@app.route('/logout')
def logout():
    logout_user()
    return jsonify({"message": "Logged out"}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create database tables if they don't exist
    app.run(host='0.0.0.0', port=5000, debug=True)