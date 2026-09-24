# Email Analysis System

A minimal web-based Email Analysis System developed using:

- Python
- Flask
- HTML
- CSS
- JavaScript
- SQLite

## Features

### Email Analysis

- Upload `.eml` files
- Extract sender
- Extract recipient
- Extract subject
- Extract date
- Extract Reply-To
- Extract Return-Path
- Extract Message-ID

### Content Analysis

- Email body extraction
- Word count
- URL detection
- Attachment detection
- Attachment filename detection
- Attachment content type

### Security Analysis

- Suspicious keyword detection
- Basic spam scoring
- Basic phishing indicators
- URL analysis
- HTTP/HTTPS checking
- IP-based URL detection
- Suspicious `@` URL detection
- Long URL detection
- Risk score
- Risk level

### History

- Store analysis results
- Search analysis history
- Delete analysis records

## Requirements

Python 3.10 or newer.

## Installation

Open a terminal in the project directory.

Create a virtual environment:

    python -m venv venv

### Windows

    venv\Scripts\activate

### Linux/macOS

    source venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

## Run

Start the application:

    python app.py

Open:

    http://127.0.0.1:5000

## Usage

1. Start the Flask application.
2. Open the website.
3. Select an `.eml` email file.
4. Click "Analyze Email".
5. Review the email information.
6. Review links and attachments.
7. Review spam and phishing indicators.
8. Check the overall risk level.
9. Visit History to view previous analyses.

## Database

SQLite is used.

The database is automatically created as:

    database.db

No separate database server is required.

## Upload Folder

Uploaded `.eml` files are stored in:

    uploads/

## Risk Calculation

The application uses a simple heuristic.

Spam indicators contribute to the spam score.

Phishing indicators contribute to the phishing score.

Links and attachments can also increase the overall risk score.

Risk levels:

- Low
- Medium
- High

## Important Note

This application is an educational email-analysis project.

The spam/phishing detection is rule-based and should not be considered a
professional security or threat-detection system.

Do not open suspicious attachments or visit suspicious links merely because
the application has analyzed them.

## Future Improvements

Possible future additions include:

- Gmail API integration
- Outlook integration
- Machine-learning spam classification
- Advanced phishing detection
- SPF/DKIM/DMARC analysis
- WHOIS/domain analysis
- Virus scanning integration
- User authentication
- Admin dashboard
- Export reports as PDF
