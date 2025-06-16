from flask import Flask, render_template, redirect, url_for, request, send_file, abort, flash, session  # type: ignore
from flask_sqlalchemy import SQLAlchemy  # type: ignore
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user  # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash  # type: ignore
import os
from urllib.parse import unquote, urlparse, parse_qs, quote
from flask_migrate import Migrate  # type: ignore
import pdfplumber  # type: ignore
import pandas as pd  # type: ignore
import httpx  # type: ignore
import unicodedata
import datetime
import re
# Import your models (ensure your models file defines db, History, User, UserActivity)
from models import db, History
from models import db, User, UserActivity

# Initialize Flask app and extensions
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database and migration
db.init_app(app)
migrate = Migrate(app, db)

# Initialize the login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Load user function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # type: ignore

# Updated log_activity function: accepts an optional file_path parameter
def log_activity(username, action, file_path=None):
    activity = History(username=username, action=action, file_path=file_path)
    db.session.add(activity)
    db.session.commit()

# Function to combine directory and filename
def combine_directory_filename(directory, filename):
    return os.path.join(directory, filename)

# Function to slugify a string (convert to safe filename)
def slugify(value, allow_unicode=False):
    value = str(value)
    if allow_unicode:
        value = unicodedata.normalize('NFKC', value)
    else:
        value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
    
    value = re.sub(r'[^\w\s-]', '', value).strip().lower()
    return re.sub(r'[-\s]+', '_', value)

# Function to remove European umlauts and convert to basic ASCII vowels
def remove_umlauts(text):
    european_umlauts = {
        'à': 'a', 'á': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a', 'å': 'a',
        'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e',
        'ì': 'i', 'í': 'i', 'î': 'i', 'ï': 'i',
        'ò': 'o', 'ó': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o', 'ø': 'o',
        'ù': 'u', 'ú': 'u', 'û': 'u', 'ü': 'u',
        'ý': 'y', 'ÿ': 'y',
    }
    return ''.join(european_umlauts.get(char, char) for char in text)

# Helper: extract a direct PDF URL from a DuckDuckGo redirect link
def get_direct_pdf_url(link):
    """
    If link is of the form //duckduckgo.com/l/?uddg=ENCODED_URL,
    extract and return the decoded ENCODED_URL. Otherwise return link.
    """
    # Ensure proper scheme
    if link.startswith('//'):
        link = 'https:' + link
    parsed = urlparse(link)
    if 'duckduckgo.com' in parsed.netloc and parsed.path.startswith('/l/'):
        qs = parse_qs(parsed.query)
        uddg = qs.get('uddg', [None])[0]
        if uddg:
            return unquote(uddg)
    return link

# Routes

# Home route (Welcome screen)
@app.route('/')
def home():
    return render_template('home.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Authenticate the user
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            log_activity(user.username, 'Logged in')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Please choose a different one.", "error")
            return render_template('register.html')

        # Create and add a new user
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

# Search PDFs using DuckDuckGo with httpx (following redirects)
def search_pdfs(query):
    encoded_query = quote(query)
    url = f"https://duckduckgo.com/html/?q={encoded_query}"
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            from bs4 import BeautifulSoup  # type: ignore
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.find_all('a', class_='result__a')
            pdf_results = []
            for result in results:
                link = result.get('href')
                if link and 'pdf' in link.lower():
                    parsed = urlparse(link)
                    file_name = os.path.basename(parsed.path) or result.get_text().strip() or "Unnamed PDF"
                    match = re.search(r'(19|20)\d{2}', file_name)
                    year = match.group() if match else "Unknown"
                    pdf_results.append({
                        "link": link,
                        "file_name": file_name,
                        "year": year
                    })
            print("Found PDF results:", pdf_results)
            return pdf_results
    except httpx.HTTPError as e:
        print(f"Failed to retrieve search results: {e}")
        return []

# Route to download a PDF using httpx, save with subdirectory, and log the file path
@app.route('/download_pdf')
@login_required
def download_pdf():
    pdf_url = request.args.get('url')
    if not pdf_url:
        return 'No PDF URL provided', 400

    # Decode twice to handle %253F → %3F → ?
    decoded = unquote(unquote(pdf_url))
    target_url = get_direct_pdf_url(decoded)

    try:
        with httpx.Client() as client:
            response = client.get(target_url)
            response.raise_for_status()

            # Create subdirectory based on current year-month
            now = datetime.datetime.now()
            subdir = os.path.join("downloads", f"{now.year}-{now.month:02d}")
            os.makedirs(subdir, exist_ok=True)

            file_path = os.path.join(subdir, f"downloaded_pdf_{current_user.username}.pdf")
            with open(file_path, 'wb') as f:  # type: ignore
                f.write(response.content)

        log_activity(current_user.username, f"Downloaded a PDF from {target_url}", file_path=file_path)
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        print(f"Error downloading the PDF: {e}")  # type: ignore
        return 'Error downloading the PDF', 500

# Route to download a PDF as CSV using httpx, save with subdirectory, and log the file path
@app.route('/download_csv')
@login_required
def download_csv():
    pdf_url = request.args.get('url')
    if not pdf_url:
        return 'No PDF URL provided', 400

    # Decode twice to handle %253F → %3F → ?
    decoded = unquote(unquote(pdf_url))
    target_url = get_direct_pdf_url(decoded)

    try:
        with httpx.Client() as client:
            response = client.get(target_url)
            response.raise_for_status()

            now = datetime.datetime.now()
            subdir = os.path.join("downloads", f"{now.year}-{now.month:02d}")
            os.makedirs(subdir, exist_ok=True)

            file_path = os.path.join(subdir, f"downloaded_pdf_{current_user.username}.pdf")
            with open(file_path, 'wb') as f:  # type: ignore
                f.write(response.content)

        # Convert the PDF to CSV
        with pdfplumber.open(file_path) as pdf:
            all_text = ""
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    all_text += text

        csv_path = os.path.join(subdir, f"downloaded_pdf_{current_user.username}.csv")
        with open(csv_path, 'w', encoding='utf-8') as csvfile:  # type: ignore
            csvfile.write(all_text)

        log_activity(current_user.username, "Downloaded a CSV", file_path=csv_path)
        return send_file(csv_path, as_attachment=True)
    except Exception as e:
        print(f"Error downloading or processing the PDF: {e}")  # type: ignore
        return 'Error processing the PDF', 500

# Dashboard route using POST-Redirect-GET
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        search_query = request.form['search_query']
        if search_query:
            cleaned_query = remove_umlauts(search_query)
            slugified_query = slugify(cleaned_query)
            directory = '/path/to/your/directory'
            file_path = combine_directory_filename(directory, slugified_query + '.pdf')
            log_activity(current_user.username, f"Searched for '{search_query}'", file_path=file_path)

            pdf_links = search_pdfs(search_query)
            session['pdf_links'] = pdf_links

        return redirect(url_for('dashboard'))
    else:
        pdf_links = session.pop('pdf_links', [])
        return render_template('dashboard.html', pdf_links=pdf_links)

# History route (explicit endpoint 'history')
@app.route('/history', endpoint='history')
@login_required
def history_view():
    history_records = History.query.order_by(History.date.desc()).all()
    return render_template('history.html', history_records=history_records)

# Activity log route (only for admin)
@app.route('/activity_log')
@login_required
def activity_log():
    if current_user.username != "admin":
        abort(403)
    logs = UserActivity.query.order_by(UserActivity.timestamp.desc()).all()
    return render_template('activity_log.html', logs=logs)

# Profile route (ensure profile.html exists in your templates folder)
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5004)
