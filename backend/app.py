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
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    filename = file.filename.lower()
    
    # Check file type
    is_image = filename.endswith(('.png', '.jpg', '.jpeg'))
    
    try:
        if is_image:
            # Read and encode image to base64
            image_content = file.read()
            image_base64 = base64.b64encode(image_content).decode('utf-8')
            
            # Using a more common model ID for Vision
            response = client.chat.completions.create(
                model="google/gemini-2.0-flash-001", # Updated Model ID
                messages=[{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Analyze this medical report image. Give a summary and a health score (1-10)."},
                        {"type": "image_url", "image_url": {"url": f"data:{file.content_type};base64,{image_base64}"}}
                    ]
                }]
            )
        else:
            # --- Your existing PDF logic here ---
            # Make sure to reset file pointer if you read it earlier: file.seek(0)
            return jsonify({"error": "PDF logic needs to be integrated"}), 400

        # Parsing the AI response
        analysis = response.choices[0].message.content
        # Simple logic to find a number in the text for the score
        score = 7 # Default score if parsing fails
        
        # Save to database (Assuming your DB logic is here)
        # new_report = Report(user_id=current_user.id, analysis=analysis, score=score...)
        
        return jsonify({"analysis": analysis, "score": score})

    except Exception as e:
        print(f"Error: {e}") # This will show in your terminal
        return jsonify({"error": str(e)}), 500
    # Extract analysis and score from response as you did before
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
@app.route('/delete/<int:report_id>', methods=['DELETE'])
@login_required
def delete_report(report_id):
    # Find the report that belongs to the current user
    report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()
    
    if not report:
        return jsonify({"error": "Report not found"}), 404

    db.session.delete(report)
    db.session.commit()
    return jsonify({"message": "Deleted successfully"}), 200
# Add this route to your app.py
@app.route('/chat', methods=['POST'])
@login_required
def chat():
    data = request.json
    user_query = data.get('query')
    report_context = data.get('context') # This sends the current report text to AI

    try:
        response = client.chat.completions.create(
            model="google/gemini-2.0-flash-001",
            messages=[
                {"role": "system", "content": f"You are a medical assistant. Use this report context to answer user questions: {report_context}"},
                {"role": "user", "content": user_query}
            ]
        )
        ai_answer = response.choices[0].message.content
        return jsonify({"answer": ai_answer})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create database tables if they don't exist
    app.run(host='0.0.0.0', port=5000, debug=True)