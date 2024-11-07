import os
import re
from flask import Flask, request, render_template, redirect, url_for, flash, send_file, session
from werkzeug.utils import secure_filename
import pytesseract
from PIL import Image
from PyPDF2 import PdfReader
from io import BytesIO
import fitz  # PyMuPDF

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Ensure this is set for session management

# Setup upload folder and allowed file extensions
UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Pytesseract setup (only needed if you are using images)
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'  # Update path for your system

# PII Regex Patterns
aadhaar_pattern = re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')
pan_pattern = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b')
dl_pattern = re.compile(r'\b[0-9]{2}[A-Z]{2}[0-9]{2,7}\b')
voter_id_pattern = re.compile(r'\b[A-Z]{3}[0-9]{7}\b')  # Voter ID pattern

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route to handle file uploads
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']

        # If the user does not select a file
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            text = extract_text(file_path)
            pii_results, masked_pii = detect_and_mask_pii(text)

            # Check if any PII was detected
            if not any(pii_results.values()):  # No PII found
                flash('NO PII DETECTED in the document. Please upload a document with PII.')
                return redirect(url_for('upload_file'))

            # Store the results in the session for later download
            detected_pii_content = f"Detected PII:\n{pii_results}\n\nMasked PII:\n{masked_pii}"
            session['detected_pii_content'] = detected_pii_content
            session['filename'] = filename

            # Check if the file is a PDF
            if file_path.lower().endswith('.pdf'):
                # Modify PDF in place
                modified_pdf_path = redact_pii_in_pdf(file_path, pii_results)
                session['modified_pdf_path'] = modified_pdf_path  # Store the modified PDF path in session
                return render_template('result.html', pii=pii_results, masked_text=masked_pii)
            else:
                return render_template('result.html', pii=pii_results, masked_text=masked_pii)

    return render_template('upload.html')

# Route to download modified document
@app.route('/download')
def download_file():
    if 'modified_pdf_path' in session:
        modified_pdf_path = session.get('modified_pdf_path')
        return send_file(modified_pdf_path, as_attachment=True, download_name='redacted_pii.pdf')
    else:
        flash('No file available for download.')
        return redirect(url_for('upload_file'))

# Function to redact PII in PDF
def redact_pii_in_pdf(pdf_path, pii_data):
    doc = fitz.open(pdf_path)
    redacted = False

    # Iterate through each page of the document
    for page_num in range(len(doc)):
        page = doc[page_num]

        # Iterate through each type of PII and its detected instances
        for pii_type, pii_list in pii_data.items():
            for pii in pii_list:
                # Search for all instances of PII on the page
                text_instances = page.search_for(pii)
                if text_instances:  # Check if there are any instances to redact
                    redacted = True
                    for inst in text_instances:
                        # Add redaction annotation (blackout)
                        page.add_redact_annot(inst, fill=(0, 0, 0))

        # Apply all redactions if any were made
        if redacted:
            page.apply_redactions()

    # If no redactions were made, inform the user
    if not redacted:
        flash('No PII instances were found to redact in the PDF.')
        return redirect(url_for('upload_file'))

    # Save the modified PDF to a new file path
    modified_pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], 'redacted_' + os.path.basename(pdf_path))
    doc.save(modified_pdf_path, deflate=True)
    doc.close()

    return modified_pdf_path

# Function to extract text from uploaded file
def extract_text(file_path):
    text = ''
    if file_path.lower().endswith('.pdf'):
        text = extract_text_from_pdf(file_path)
    elif file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
        text = extract_text_from_image(file_path)
    elif file_path.lower().endswith('.txt'):
        with open(file_path, 'r') as file:
            text = file.read()
    return text

def extract_text_from_image(image_path):
    return pytesseract.image_to_string(Image.open(image_path), config='--psm 6')

def extract_text_from_pdf(pdf_path):
    text = ""
    reader = PdfReader(pdf_path)
    for page in reader.pages:
        text += page.extract_text()
    return text

# Helper function to mask PII
def mask_pii(match):
    return 'X' * len(match.group())

# Function to detect and mask PII in text
def detect_and_mask_pii(text):
    masked_pii = {
        'aadhaar': [mask_pii(match) for match in aadhaar_pattern.finditer(text)],
        'pan': [mask_pii(match) for match in pan_pattern.finditer(text)],
        'driving_license': [mask_pii(match) for match in dl_pattern.finditer(text)],
        'voter_id': [mask_pii(match) for match in voter_id_pattern.finditer(text)]  # Masking Voter ID
    }

    pii_found = {
        'aadhaar': aadhaar_pattern.findall(text),
        'pan': pan_pattern.findall(text),
        'driving_license': dl_pattern.findall(text),
        'voter_id': voter_id_pattern.findall(text)  # Finding Voter ID
    }

    return pii_found, masked_pii

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
