import os
import re
import sqlite3
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

app = Flask(__name__)

app.secret_key = "email-analysis-secret-key"

DATABASE = "database.db"
UPLOAD_FOLDER = "uploads"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            sender TEXT,
            recipient TEXT,
            reply_to TEXT,
            return_path TEXT,
            subject TEXT,
            email_date TEXT,
            message_id TEXT,
            word_count INTEGER DEFAULT 0,
            link_count INTEGER DEFAULT 0,
            attachment_count INTEGER DEFAULT 0,
            spam_score INTEGER DEFAULT 0,
            phishing_score INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT,
            suspicious_words TEXT,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------
# EMAIL BODY EXTRACTION
# --------------------------------------------------

def extract_body(message):
    plain_text = ""
    html_text = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    plain_text += part.get_content()
                except Exception:
                    pass

            elif content_type == "text/html":
                try:
                    html_text += part.get_content()
                except Exception:
                    pass

    else:
        try:
            content_type = message.get_content_type()

            if content_type == "text/html":
                html_text = message.get_content()
            else:
                plain_text = message.get_content()

        except Exception:
            pass

    # Prefer plain text
    if plain_text.strip():
        return plain_text.strip()

    # Basic HTML-to-text conversion
    if html_text.strip():
        text = re.sub(r"<[^>]+>", " ", html_text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    return ""


# --------------------------------------------------
# URL EXTRACTION
# --------------------------------------------------

def extract_links(body):
    pattern = r'https?://[^\s<>"\']+'

    links = re.findall(pattern, body)

    cleaned_links = []

    for link in links:
        link = link.rstrip(".,);]")

        if link not in cleaned_links:
            cleaned_links.append(link)

    return cleaned_links


# --------------------------------------------------
# ATTACHMENT EXTRACTION
# --------------------------------------------------

def extract_attachments(message):
    attachments = []

    for part in message.iter_attachments():

        filename = part.get_filename()

        if filename:
            content_type = part.get_content_type()

            attachments.append({
                "filename": filename,
                "content_type": content_type
            })

    return attachments


# --------------------------------------------------
# SUSPICIOUS KEYWORDS
# --------------------------------------------------

SUSPICIOUS_WORDS = [
    "urgent",
    "immediately",
    "verify",
    "verification",
    "password",
    "account suspended",
    "account locked",
    "click here",
    "winner",
    "congratulations",
    "free",
    "login",
    "bank",
    "confirm",
    "security alert",
    "limited time",
    "payment required",
    "update your account"
]


# --------------------------------------------------
# SPAM ANALYSIS
# --------------------------------------------------

def analyze_spam(subject, body):

    score = 0
    indicators = []

    text = (subject + " " + body).lower()

    for word in SUSPICIOUS_WORDS:

        if word in text:

            score += 5

            indicators.append(word)

    # Excessive exclamation marks
    if text.count("!") >= 3:
        score += 5
        indicators.append("Excessive exclamation marks")

    # Excessive capital letters
    letters = [c for c in body if c.isalpha()]

    if len(letters) > 20:

        capitals = [c for c in letters if c.isupper()]

        if len(capitals) / len(letters) > 0.45:
            score += 10
            indicators.append("Excessive capital letters")

    return min(score, 100), indicators


# --------------------------------------------------
# PHISHING ANALYSIS
# --------------------------------------------------

def analyze_phishing(sender, body, links):

    score = 0
    indicators = []

    text = body.lower()

    phishing_words = [
        "verify your account",
        "confirm your account",
        "login immediately",
        "password",
        "account suspended",
        "click here",
        "security alert",
        "verify now"
    ]

    for word in phishing_words:

        if word in text:

            score += 10
            indicators.append(word)

    # URL analysis
    for link in links:

        try:
            parsed = urlparse(link)

            domain = parsed.netloc.lower()

            # IP address used instead of domain
            if re.match(
                r"^\d{1,3}(\.\d{1,3}){3}$",
                domain.split(":")[0]
            ):
                score += 20
                indicators.append("URL uses an IP address")

            # Suspicious URL characters
            if "@" in link:
                score += 15
                indicators.append("Suspicious @ symbol in URL")

            # Very long URL
            if len(link) > 120:
                score += 10
                indicators.append("Very long URL")

            # HTTP instead of HTTPS
            if parsed.scheme.lower() == "http":
                score += 5
                indicators.append("URL does not use HTTPS")

        except Exception:
            pass

    return min(score, 100), indicators


# --------------------------------------------------
# RISK CALCULATION
# --------------------------------------------------

def calculate_risk(spam_score, phishing_score, links, attachments):

    risk_score = (
        spam_score * 0.35 +
        phishing_score * 0.50
    )

    if len(links) > 3:
        risk_score += 5

    if len(attachments) > 0:
        risk_score += 5

    risk_score = min(int(risk_score), 100)

    if risk_score < 30:
        risk_level = "Low"

    elif risk_score < 60:
        risk_level = "Medium"

    else:
        risk_level = "High"

    return risk_score, risk_level


# --------------------------------------------------
# EMAIL ANALYSIS
# --------------------------------------------------

def analyze_email(filepath):

    with open(filepath, "rb") as file:

        message = BytesParser(
            policy=policy.default
        ).parse(file)

    sender = message.get("From", "Unknown")
    recipient = message.get("To", "Unknown")
    reply_to = message.get("Reply-To", "Not available")
    return_path = message.get("Return-Path", "Not available")
    subject = message.get("Subject", "No Subject")
    email_date = message.get("Date", "Unknown")
    message_id = message.get("Message-ID", "Not available")

    body = extract_body(message)

    links = extract_links(body)

    attachments = extract_attachments(message)

    words = re.findall(
        r"\b[\w'-]+\b",
        body
    )

    word_count = len(words)

    spam_score, spam_indicators = analyze_spam(
        subject,
        body
    )

    phishing_score, phishing_indicators = analyze_phishing(
        sender,
        body,
        links
    )

    all_indicators = list(
        dict.fromkeys(
            spam_indicators + phishing_indicators
        )
    )

    risk_score, risk_level = calculate_risk(
        spam_score,
        phishing_score,
        links,
        attachments
    )

    return {
        "sender": sender,
        "recipient": recipient,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "email_date": email_date,
        "message_id": message_id,
        "body": body,
        "links": links,
        "attachments": attachments,
        "word_count": word_count,
        "link_count": len(links),
        "attachment_count": len(attachments),
        "spam_score": spam_score,
        "phishing_score": phishing_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": all_indicators
    }


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def index():

    return render_template("index.html")


# --------------------------------------------------
# ANALYZE EMAIL
# --------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():

    if "email_file" not in request.files:

        flash("No file selected.")

        return redirect(url_for("index"))

    file = request.files["email_file"]

    if file.filename == "":

        flash("Please select an email file.")

        return redirect(url_for("index"))

    if not file.filename.lower().endswith(".eml"):

        flash("Only .eml files are supported.")

        return redirect(url_for("index"))

    # Basic filename safety
    filename = os.path.basename(file.filename)

    filepath = os.path.join(
        UPLOAD_FOLDER,
        filename
    )

    try:

        file.save(filepath)

        result = analyze_email(filepath)

        conn = get_db()

        cursor = conn.execute("""
            INSERT INTO analyses (
                filename,
                sender,
                recipient,
                reply_to,
                return_path,
                subject,
                email_date,
                message_id,
                word_count,
                link_count,
                attachment_count,
                spam_score,
                phishing_score,
                risk_score,
                risk_level,
                suspicious_words
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            filename,
            result["sender"],
            result["recipient"],
            result["reply_to"],
            result["return_path"],
            result["subject"],
            result["email_date"],
            result["message_id"],
            result["word_count"],
            result["link_count"],
            result["attachment_count"],
            result["spam_score"],
            result["phishing_score"],
            result["risk_score"],
            result["risk_level"],
            ", ".join(result["indicators"])
        ))

        analysis_id = cursor.lastrowid

        conn.commit()
        conn.close()

        result["id"] = analysis_id
        result["filename"] = filename

        return render_template(
            "result.html",
            result=result
        )

    except Exception as error:

        flash(
            "Unable to analyze this email: "
            + str(error)
        )

        return redirect(url_for("index"))


# --------------------------------------------------
# HISTORY
# --------------------------------------------------

@app.route("/history")
def history():

    search = request.args.get(
        "search",
        ""
    ).strip()

    conn = get_db()

    if search:

        analyses = conn.execute("""
            SELECT *
            FROM analyses
            WHERE
                sender LIKE ?
                OR recipient LIKE ?
                OR subject LIKE ?
                OR filename LIKE ?
            ORDER BY analyzed_at DESC
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        )).fetchall()

    else:

        analyses = conn.execute("""
            SELECT *
            FROM analyses
            ORDER BY analyzed_at DESC
        """).fetchall()

    conn.close()

    return render_template(
        "history.html",
        analyses=analyses,
        search=search
    )


# --------------------------------------------------
# DELETE ANALYSIS
# --------------------------------------------------

@app.route("/delete/<int:analysis_id>", methods=["POST"])
def delete_analysis(analysis_id):

    conn = get_db()

    analysis = conn.execute("""
        SELECT filename
        FROM analyses
        WHERE id = ?
    """, (analysis_id,)).fetchone()

    if analysis:

        filepath = os.path.join(
            UPLOAD_FOLDER,
            analysis["filename"]
        )

        if os.path.exists(filepath):
            os.remove(filepath)

        conn.execute("""
            DELETE FROM analyses
            WHERE id = ?
        """, (analysis_id,))

        conn.commit()

    conn.close()

    return redirect(url_for("history"))


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True
    )
