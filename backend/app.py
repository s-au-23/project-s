import os
import re
from datetime import datetime
from flask import Flask, request, jsonify, render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI
import PyPDF2

template_dir = os.path.abspath('../frontend')
app = Flask(__name__, template_folder=template_dir)

# Config
app.config['SECRET_KEY'] = 'health_ai_openrouter_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lab_reports.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# OpenRouter Setup
# This tells the OpenAI library to send requests to OpenRouter instead
client = OpenAI(
  base_url="https://openrouter.ai/api/v1",
  api_key="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", # Paste your OpenRouter key here
)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

# Models
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
    name = current_user.username if current_user.is_authenticated else None
    return render_template('index.html', name=name)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if User.query.filter_by(username=data.get('username')).first():
        return jsonify({"error": "User exists"}), 400
    db.session.add(User(username=data.get('username'), password=generate_password_hash(data.get('password'))))
    db.session.commit()
    return jsonify({"message": "Success"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password, data.get('password')):
        login_user(user, remember=True)
        return jsonify({"message": "In"}), 200
    return jsonify({"error": "Fail"}), 401

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if not file: return jsonify({"error": "No file"}), 400
    
    try:
        # Extract PDF Text
        reader = PyPDF2.PdfReader(file)
        text = "".join([p.extract_text() for p in reader.pages if p.extract_text()])
        
        # OpenRouter API Call (Using Gemini through OpenRouter)
        response = client.chat.completions.create(
           model="google/gemini-2.0-flash-001", # You can change this to "openai/gpt-4o"
            messages=[
        {"role": "user", "content": f"Analyze this lab report... {text}"}
    ]
        )
        
        ai_text = response.choices[0].message.content
        score = int(re.search(r"SCORE:\s*(\d+)", ai_text).group(1)) if re.search(r"SCORE:\s*(\d+)", ai_text) else 5
        
        report = Report(user_id=current_user.id, summary=ai_text, score=score, date=datetime.now().strftime("%Y-%m-%d"))
        db.session.add(report)
        db.session.commit()
        
        return jsonify({"analysis": ai_text, "score": score})
    except Exception as e:
        print(f"ERROR: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/history')
@login_required
def history():
    reports = Report.query.filter_by(user_id=current_user.id).all()
    return jsonify([{"score": r.score, "summary": r.summary, "date": r.date} for r in reports])

@app.route('/logout')
def logout():
    logout_user(); return jsonify({"message": "Out"}), 200

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)