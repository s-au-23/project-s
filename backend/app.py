import os
import json
import requests
import pypdf
import re
from io import BytesIO
from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for
from flask_cors import CORS
from reportlab.pdfgen import canvas
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# 1. Initialize App and Config
app = Flask(__name__, template_folder="../frontend", static_folder="../frontend")
CORS(app)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_medical_app_secret_key' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 2. Initialize Database and Login Manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth_page'

# --- MODELS ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class LabHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.String(10))
    summary = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=db.func.current_timestamp())

@login_manager.user_loader
def load_user(user_id):
    # Modern SQLAlchemy 2.0 syntax
    return db.session.get(User, int(user_id))

# Create Database tables
with app.app_context():
    db.create_all()

# AI CONFIG
OPENROUTER_API_KEY = "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"
# Using a stable model ID to avoid 404/400 errors
MODEL_NAME = "google/gemini-2.0-flash-001" 

# --- AUTH ROUTES ---

@app.route('/auth')
def auth_page():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('auth.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data.get('username') or not data.get('password'):
        return jsonify({"error": "Missing credentials"}), 400
    
    hashed_password = generate_password_hash(data['password'])
    new_user = User(username=data['username'], password=hashed_password)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Account created! Please login."}), 201
    except Exception:
        db.session.rollback()
        return jsonify({"error": "User already exists!"}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    # Modern filter syntax
    user = db.session.execute(db.select(User).filter_by(username=data['username'])).scalar_one_or_none()
    
    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({"message": "Login successful!"}), 200
    return jsonify({"error": "Invalid username or password"}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth_page'))

# --- MAIN APP ROUTES ---

@app.route('/')
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('auth_page'))
    return render_template('index.html', name=current_user.username)

@app.route('/delete-history/<int:report_id>', methods=['DELETE'])
@login_required
def delete_history_item(report_id):
    report = db.session.execute(
        db.select(LabHistory).filter_by(id=report_id, user_id=current_user.id)
    ).scalar_one_or_none()
    
    if report:
        db.session.delete(report)
        db.session.commit()
        return jsonify({"message": "Report deleted successfully"}), 200
    
    return jsonify({"error": "Report not found"}), 404

@app.route('/upload', methods=['POST'])
@login_required 
def upload_pdf():
    extracted_text = ""
    if 'file' not in request.files:
        return jsonify({"error": "No file selected"}), 400
    
    file = request.files['file']
    try:
        reader = pypdf.PdfReader(file)
        for page in reader.pages[:3]:
            text = page.extract_text()
            if text: extracted_text += text + "\n"
        
        if not extracted_text.strip():
            return jsonify({"error": "PDF is unreadable"}), 400

        payload = {
            "model": MODEL_NAME,
            "messages": [
                {"role": "system", "content": "Analyze report. Format FIRST line: SCORE: [number]. Summary below."},
                {"role": "user", "content": extracted_text[:4000]}
            ]
        }
        
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:5000",
            },
            data=json.dumps(payload)
        )
        
        result = response.json()

        if response.status_code == 200 and 'choices' in result:
            ai_content = result['choices'][0]['message']['content']
            score_match = re.search(r"SCORE:\s*(\d+)", ai_content, re.IGNORECASE)
            extracted_score = score_match.group(1) if score_match else "N/A"

            new_entry = LabHistory(user_id=current_user.id, score=extracted_score, summary=ai_content)
            db.session.add(new_entry)
            db.session.commit()
            return jsonify({"analysis": ai_content})
        else:
            error_detail = result.get('error', {}).get('message', 'AI service failed')
            return jsonify({"error": f"AI Error: {error_detail}"}), response.status_code

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/history', methods=['GET'])
@login_required
def get_history():
    # Order history by newest first
    stmt = db.select(LabHistory).filter_by(user_id=current_user.id).order_by(LabHistory.date.desc())
    history = db.session.execute(stmt).scalars().all()
    
    results = [
        {
            "id": h.id, 
            "score": h.score, 
            "summary": h.summary, 
            "date": h.date.strftime('%Y-%m-%d')
        } for h in history
    ]
    return jsonify(results)

@app.route('/settings')
@login_required
def settings_page():
    return render_template('settings.html', name=current_user.username)

@app.route('/update-password', methods=['POST'])
@login_required
def update_password():
    data = request.json
    new_password = data.get('password')
    if new_password:
        try:
            current_user.password = generate_password_hash(new_password)
            db.session.commit()
            return jsonify({"message": "Password updated successfully!"})
        except Exception:
            db.session.rollback()
            return jsonify({"error": "Database error"}), 500
    return jsonify({"error": "Invalid password"}), 400

@app.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    try:
        # Delete history first due to foreign key constraints
        db.session.execute(db.delete(LabHistory).filter_by(user_id=current_user.id))
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        return jsonify({"message": "Account deleted"})
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Failed to delete account"}), 500

@app.route('/download-pdf', methods=['POST'])
@login_required
def download_pdf():
    try:
        data = request.json
        content = data.get('text', '')
        buffer = BytesIO()
        p = canvas.Canvas(buffer)
        p.setFont("Helvetica-Bold", 14)
        p.drawString(100, 800, "Medical Analysis Summary")
        p.setFont("Helvetica", 10)
        y = 750
        for line in content.split('\n'):
            # Text wrapping logic for PDF
            if y < 50: # New page if bottom reached
                p.showPage()
                y = 800
                p.setFont("Helvetica", 10)
            p.drawString(100, y, line[:95])
            y -= 15
        p.save()
        buffer.seek(0) 
        return send_file(buffer, as_attachment=True, download_name="Analysis.pdf", mimetype='application/pdf')
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)