import os
import json
import requests
import pypdf
from io import BytesIO
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from reportlab.pdfgen import canvas

app = Flask(__name__, template_folder="../frontend", static_folder="../frontend")
CORS(app)

# --- CONFIGURATION ---
OPENROUTER_API_KEY = "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"
MODEL_NAME = "openrouter/auto"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_pdf():
    extracted_text = ""
    
    if 'file' not in request.files:
        return jsonify({"error": "No file selected"}), 400
    
    file = request.files['file']
    
    try:
        # 1. Extract text from the PDF FIRST
        reader = pypdf.PdfReader(file)
        for page in reader.pages[:3]: # Read up to 3 pages
            text = page.extract_text()
            if text:
                extracted_text += text + "\n"
        
        if not extracted_text.strip():
            return jsonify({"error": "Could not read text from this PDF."}), 400

        # 2. Prepare the AI Payload with Health Score instructions
        payload = {
            "model": MODEL_NAME,
            "messages": [
                {
                    "role": "system", 
                    "content": """You are a medical lab expert. Analyze the provided lab report and:
                    1. Assign a 'Health Score' from 1 to 10 (10 is perfect, 1 is critical).
                    2. Format the VERY FIRST line of your response exactly like this: SCORE: [number]
                    3. Then, provide a simple summary of the report below that line.
                    Example:
                    SCORE: 8
                    Your report shows good overall health..."""
                },
                {
                    "role": "user", 
                    "content": f"Lab Report Text:\n{extracted_text[:4000]}"
                }
            ]
        }

        # 3. Call OpenRouter
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
            },
            data=json.dumps(payload)
        )

        result = response.json()

        # 4. Handle Response
        if response.status_code == 200 and 'choices' in result:
            ai_content = result['choices'][0]['message']['content']
            return jsonify({"analysis": ai_content})
        else:
            error_msg = result.get('error', {}).get('message', 'API is busy')
            print(f"❌ API Error: {error_msg}")
            return jsonify({"error": error_msg}), response.status_code

    except Exception as e:
        print(f"❌ Server Error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/download-pdf', methods=['POST'])
def download_pdf():
    try:
        data = request.json
        content = data.get('text', 'No data provided')

        buffer = BytesIO()
        p = canvas.Canvas(buffer)
        p.setFont("Helvetica-Bold", 14)
        p.drawString(100, 800, "Medical Analysis Summary")
        p.line(100, 785, 500, 785)
        
        p.setFont("Helvetica", 10)
        y = 750
        for line in content.split('\n'):
            # Text wrapping: simple check to prevent overflow
            if y < 50:
                p.showPage()
                y = 800
            p.drawString(100, y, line[:95])
            y -= 15

        p.showPage()
        p.save()
        buffer.seek(0) 
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name="Analysis_Report.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        print(f"PDF Generation Error: {e}")
        return str(e), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)