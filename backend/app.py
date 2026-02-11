import os
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
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key="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",
    default_headers={
        "HTTP-Referer": "http://localhost:5000",
        "X-Title": "Project-G Health AI",
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
        # Default score if AI doesn't return one clearly
        score = 7 

        if is_image:
            # --- IMAGE PROCESSING ---
            image_content = file.read()
            image_base64 = base64.b64encode(image_content).decode('utf-8')
            
            response = client.chat.completions.create(
                model="google/gemini-2.0-flash-001",
                messages=[{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Analyze this medical report image. Provide a detailed summary and a health score from 1 to 10 based on the results."},
                        {"type": "image_url", "image_url": {"url": f"data:{file.content_type};base64,{image_base64}"}}
                    ]
                }]
            )
            analysis = response.choices[0].message.content
        else:
            # --- PDF PROCESSING ---
            pdf_reader = PyPDF2.PdfReader(file)
            text_content = ""
            for page in pdf_reader.pages:
                text_content += page.extract_text()
            
            if not text_content.strip():
                return jsonify({"error": "PDF is empty or non-readable text"}), 400

            response = client.chat.completions.create(
                model="google/gemini-2.0-flash-001",
                messages=[
                    {"role": "system", "content": "You are a medical assistant. Analyze the report text. Provide a summary and a health score from 1 to 10."},
                    {"role": "user", "content": text_content}
                ]
            )
            analysis = response.choices[0].message.content

        # Simple Logic to extract score from AI text (looking for a digit 1-10)
        score_match = re.search(r'Score:\s*(\d+)', analysis)
        if score_match:
            score = int(score_match.group(1))
        
        # --- SAVE TO DATABASE ---
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
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/history')
@login_required
def history():
    # Fetch reports and return ID for deletion purpose
    reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.id.desc()).all()
    return jsonify([{"id": r.id, "score": r.score, "summary": r.summary, "date": r.date} for r in reports])

@app.route('/logout')
def logout():
    logout_user()
    return jsonify({"message": "Logged out"}), 200

@app.route('/delete/<int:report_id>', methods=['DELETE'])
@login_required
def delete_report(report_id):
    report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()
    if not report:
        return jsonify({"error": "Report not found"}), 404

    db.session.delete(report)
    db.session.commit()
    return jsonify({"message": "Deleted successfully"}), 200

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    data = request.json
    user_query = data.get('query')
    report_context = data.get('context')

    try:
        response = client.chat.completions.create(
            model="google/gemini-2.0-flash-001",
            messages=[
                {"role": "system", "content": f"You are a medical assistant. Context: {report_context}"},
                {"role": "user", "content": user_query}
            ]
        )
        ai_answer = response.choices[0].message.content
        return jsonify({"answer": ai_answer})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)