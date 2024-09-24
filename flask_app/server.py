import os
from flask import Flask, request, send_file, jsonify, render_template
import pandas as pd
import spacy
import re


app = Flask(__name__)

# Load the SpaCy model
nlp = spacy.load('en_core_web_sm')

# Function to mask sensitive text with ********
def mask_sensitive(text):
    return '********'

# Function to recognize and mask sensitive data in the message
def anonymize_message(message):
    doc = nlp(message)
    anonymized_message = message
    
    # Mask recognized entities: PERSON (names), EMAIL, ORG (organizations)
    for ent in doc.ents:
        if ent.label_ in ['PERSON', 'EMAIL', 'ORG']:
            anonymized_message = anonymized_message.replace(ent.text, mask_sensitive(ent.text))
    
    # Mask SSNs based on the pattern 'XXX-XX-XXXX'
    ssns = re.findall(r'\d{3}-\d{2}-\d{4}', message)
    for ssn in ssns:
        anonymized_message = anonymized_message.replace(ssn, mask_sensitive(ssn))

    # Mask emails using regex
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', message)
    for email in emails:
        anonymized_message = anonymized_message.replace(email, mask_sensitive(email))    
    
    # Mask phone numbers based on the pattern '(XXX) XXX-XXXX' or 'XXX-XXX-XXXX'
    phone_numbers = re.findall(r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', message)
    for phone in phone_numbers:
        anonymized_message = anonymized_message.replace(phone, mask_sensitive(phone))
    
    return anonymized_message

# Route to open main page
@app.route('/')
def index():
    return render_template('/index.html')


# Route to upload CSV, anonymize data, and send the result back
@app.route('/anonymize', methods=['POST'])
def anonymize_csv():

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Read the CSV file into a DataFrame
    df = pd.read_csv(file)

    # Apply anonymization to the 'Message' column
    df['Anonymized_Message'] = df['Message'].apply(anonymize_message)

    # Save the anonymized data to a CSV file
    output_file = 'anonymized_sensitive_data.csv'
    df.to_csv(output_file, index=False)

    # Send the anonymized CSV file back to the client
    return send_file(output_file, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
