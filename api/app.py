import os
import json
import logging
import io
import csv
from flask import Flask, request, session, flash, redirect, url_for, render_template, jsonify, make_response
from datetime import datetime
import pytz
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
from functools import wraps

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Set secret key with a fallback for local development
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    logger.warning("SECRET_KEY not set in environment. Using fallback for local development.")
    app.secret_key = "local-development-secret-key-please-change"

# Database connection (configurable for Postgres or SQLite)
# Default to SQLite for local testing; use Postgres on Vercel
USE_SQLITE = os.getenv("VERCEL") != "1"  # True for local, False on Vercel

if USE_SQLITE:
    import sqlite3

    def get_db_connection():
        logger.info("Using SQLite database: form_approval_system.db")
        conn = sqlite3.connect('form_approval_system.db')
        conn.row_factory = sqlite3.Row
        return conn
else:
    def get_db_connection():
        postgres_url = os.getenv("POSTGRES_URL")
        if not postgres_url:
            raise ValueError("POSTGRES_URL environment variable is not set. Please configure it in your environment.")
        logger.info(f"Using Postgres database with POSTGRES_URL: {postgres_url}")
        try:
            conn = psycopg2.connect(
                postgres_url,
                cursor_factory=RealDictCursor
            )
            return conn
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise

def init_db():
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if USE_SQLITE:
            # SQLite schema
            logger.info("Initializing SQLite schema")
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT,
                approved INTEGER DEFAULT 0,
                created_at TEXT,
                email TEXT
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS forms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                request_id TEXT UNIQUE,
                approved_id TEXT,
                status TEXT,
                created_at TEXT,
                acknowledged INTEGER DEFAULT 0,
                assigned_dummy_user_id INTEGER,
                data TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(assigned_dummy_user_id) REFERENCES users(id)
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question_text TEXT,
                question_type TEXT,
                options TEXT,
                position INTEGER
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                timestamp TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )''')
            c.execute("SELECT * FROM users WHERE username = 'superadmin'")
            if not c.fetchall():
                hashed_password = bcrypt.hashpw('superadmin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (?, ?, ?, ?, ?, ?)",
                          ('superadmin', hashed_password, 'super_admin', 1, '2025-05-16 13:00:00', 'superadmin@example.com'))
                hashed_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (?, ?, ?, ?, ?, ?)",
                          ('admin', hashed_password, 'admin', 1, '2025-05-16 13:00:00', 'admin@example.com'))
                hashed_password = bcrypt.hashpw('user123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (?, ?, ?, ?, ?, ?)",
                          ('user', hashed_password, 'user', 1, '2025-05-16 13:00:00', 'user@example.com'))
        else:
            # Postgres schema
            logger.info("Initializing Postgres schema")
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT,
                approved INTEGER DEFAULT 0,
                created_at TEXT,
                email TEXT
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS forms (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                request_id TEXT UNIQUE,
                approved_id TEXT,
                status TEXT,
                created_at TEXT,
                acknowledged INTEGER DEFAULT 0,
                assigned_dummy_user_id INTEGER,
                data TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(assigned_dummy_user_id) REFERENCES users(id)
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                question_text TEXT,
                question_type TEXT,
                options TEXT,
                position INTEGER
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                action TEXT,
                timestamp TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )''')
            c.execute("SELECT * FROM users WHERE username = 'superadmin'")
            if not c.fetchall():
                hashed_password = bcrypt.hashpw('superadmin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (%s, %s, %s, %s, %s, %s)",
                          ('superadmin', hashed_password, 'super_admin', 1, '2025-05-16 13:00:00', 'superadmin@example.com'))
                hashed_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (%s, %s, %s, %s, %s, %s)",
                          ('admin', hashed_password, 'admin', 1, '2025-05-16 13:00:00', 'admin@example.com'))
                hashed_password = bcrypt.hashpw('user123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (%s, %s, %s, %s, %s, %s)",
                          ('user', hashed_password, 'user', 1, '2025-05-16 13:00:00', 'user@example.com'))
        conn.commit()
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise
    finally:
        if conn is not None:
            conn.close()

with app.app_context():
    init_db()

# Helper function to log actions
def log_action(user_id, action):
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        tz = pytz.timezone('Asia/Kolkata')
        timestamp = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
        if USE_SQLITE:
            c.execute("INSERT INTO logs (user_id, action, timestamp) VALUES (?, ?, ?)", (user_id, action, timestamp))
        else:
            c.execute("INSERT INTO logs (user_id, action, timestamp) VALUES (%s, %s, %s)", (user_id, action, timestamp))
        conn.commit()
    except Exception as e:
        logger.error(f"Logging error: {e}")
    finally:
        if conn is not None:
            conn.close()

# Error handler
@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    return render_template('error.html', error=str(e)), 500

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            if USE_SQLITE:
                c.execute("SELECT * FROM users WHERE username = ?", (username,))
            else:
                c.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = c.fetchone()
            if (user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')) 
                and user['approved'] == 1):
                session['user_id'] = user['id']
                session['role'] = user['role']
                session['username'] = user['username']
                flash('Login successful!', 'success')
                log_action(user['id'], f"User {username} logged in")
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password, or account not approved.', 'danger')
                return redirect(url_for('login'))
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
            return redirect(url_for('login'))
        finally:
            if conn is not None:
                conn.close()
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        tz = pytz.timezone('Asia/Kolkata')
        created_at = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            if USE_SQLITE:
                c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (?, ?, ?, ?, ?, ?)",
                          (username, hashed_password, 'user', 0, created_at, email))
            else:
                c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (%s, %s, %s, %s, %s, %s)",
                          (username, hashed_password, 'user', 0, created_at, email))
            conn.commit()
            flash('Sign-up successful! Please wait for approval.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('signup'))
        finally:
            if conn is not None:
                conn.close()
    return render_template('signup.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            if USE_SQLITE:
                c.execute("SELECT * FROM users WHERE email = ?", (email,))
            else:
                c.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = c.fetchone()
            if user:
                flash('Password reset link sent to your email (not implemented).', 'success')
            else:
                flash('Email not found.', 'danger')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
            return redirect(url_for('forgot_password'))
        finally:
            if conn is not None:
                conn.close()
    return render_template('forgot_password.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('login'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if session['role'] == 'super_admin':
            c.execute("SELECT status, COUNT(*) as count FROM forms GROUP BY status")
        elif session['role'] == 'admin':
            c.execute("SELECT status, COUNT(*) as count FROM forms WHERE status IN ('Submitted', 'Approved') GROUP BY status")
        elif session['role'] == 'dummy_user':
            if USE_SQLITE:
                c.execute("SELECT status, COUNT(*) as count FROM forms WHERE assigned_dummy_user_id = ? GROUP BY status", (session['user_id'],))
            else:
                c.execute("SELECT status, COUNT(*) as count FROM forms WHERE assigned_dummy_user_id = %s GROUP BY status", (session['user_id'],))
        else:
            if USE_SQLITE:
                c.execute("SELECT status, COUNT(*) as count FROM forms WHERE user_id = ? GROUP BY status", (session['user_id'],))
            else:
                c.execute("SELECT status, COUNT(*) as count FROM forms WHERE user_id = %s GROUP BY status", (session['user_id'],))
        stats = c.fetchall()
        stats_dict = {row['status']: row['count'] for row in stats}
        return render_template('dashboard.html', stats=stats_dict)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/raise_request', methods=['GET', 'POST'])
def raise_request():
    if 'user_id' not in session or session['role'] in ['admin', 'super_admin', 'dummy_user']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM questions ORDER BY position")
            questions = c.fetchall()
            form_data = {}
            for q in questions:
                form_data[q['question_text']] = request.form.get(q['question_text'], '')
            c.execute("SELECT COUNT(*) as count FROM forms")
            count = c.fetchone()['count'] + 1
            request_id = f"RR{count:05d}"
            tz = pytz.timezone('Asia/Kolkata')
            created_at = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
            if USE_SQLITE:
                c.execute("INSERT INTO forms (user_id, request_id, status, created_at, data) VALUES (?, ?, ?, ?, ?)",
                          (session['user_id'], request_id, 'Submitted', created_at, json.dumps(form_data)))
            else:
                c.execute("INSERT INTO forms (user_id, request_id, status, created_at, data) VALUES (%s, %s, %s, %s, %s)",
                          (session['user_id'], request_id, 'Submitted', created_at, json.dumps(form_data)))
            conn.commit()
            flash(f'Request submitted successfully! Request ID: {request_id}', 'success')
            log_action(session['user_id'], f"Submitted request {request_id}")
            return redirect(url_for('raise_request_confirmation', request_id=request_id))
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
            return redirect(url_for('raise_request'))
        finally:
            if conn is not None:
                conn.close()
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM questions ORDER BY position")
        questions = c.fetchall()
        return render_template('raise_request.html', questions=questions)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/raise_request_confirmation/<request_id>')
def raise_request_confirmation(request_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if USE_SQLITE:
            c.execute("SELECT * FROM forms WHERE request_id = ? AND user_id = ?", (request_id, session['user_id']))
        else:
            c.execute("SELECT * FROM forms WHERE request_id = %s AND user_id = %s", (request_id, session['user_id']))
        form = c.fetchone()
        if not form:
            flash('Request not found.', 'danger')
            return redirect(url_for('dashboard'))
        form_data = json.loads(form['data']) if form['data'] else {}
        return render_template('raise_request_confirmation.html', form=form, form_data=form_data)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/manage_requests', methods=['GET', 'POST'])
def manage_requests():
    if 'user_id' not in session or session['role'] not in ['admin', 'super_admin']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    search_query = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        query = "SELECT f.*, u.username FROM forms f JOIN users u ON f.user_id = u.id WHERE 1=1"
        params = []
        if search_query:
            query += " AND f.request_id ILIKE %s" if not USE_SQLITE else " AND f.request_id LIKE ?"
            params.append(f"%{search_query}%")
        if status_filter:
            query += " AND f.status = %s" if not USE_SQLITE else " AND f.status = ?"
            params.append(status_filter)
        if date_from:
            query += " AND f.created_at >= %s" if not USE_SQLITE else " AND f.created_at >= ?"
            params.append(date_from)
        if date_to:
            query += " AND f.created_at <= %s" if not USE_SQLITE else " AND f.created_at <= ?"
            params.append(date_to)
        c.execute(query + " ORDER BY f.created_at DESC", params)
        forms = c.fetchall()
        c.execute("SELECT id, username FROM users WHERE role = 'dummy_user'")
        dummy_users = c.fetchall()
        return render_template('manage_requests.html', forms=forms, dummy_users=dummy_users, search_query=search_query, status_filter=status_filter, date_from=date_from, date_to=date_to)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/approve_request/<int:form_id>', methods=['POST'])
def approve_request(form_id):
    if 'user_id' not in session or session['role'] not in ['admin', 'super_admin']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    dummy_user_id = request.form.get('dummy_user_id')
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) as count FROM forms WHERE approved_id IS NOT NULL")
        count = c.fetchone()['count'] + 1
        approved_id = f"AA{count:05d}"
        if USE_SQLITE:
            c.execute("UPDATE forms SET status = ?, approved_id = ?, assigned_dummy_user_id = ? WHERE id = ? AND status = ?",
                      ('Approved', approved_id, dummy_user_id, form_id, 'Submitted'))
        else:
            c.execute("UPDATE forms SET status = %s, approved_id = %s, assigned_dummy_user_id = %s WHERE id = %s AND status = %s",
                      ('Approved', approved_id, dummy_user_id, form_id, 'Submitted'))
        if c.rowcount == 0:
            flash('Request not found or already processed.', 'danger')
        else:
            conn.commit()
            flash(f'Request approved! Approved ID: {approved_id}', 'success')
            log_action(session['user_id'], f"Approved request {form_id} with Approved ID {approved_id}")
        return redirect(url_for('manage_requests'))
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('manage_requests'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/reject_request/<int:form_id>')
def reject_request(form_id):
    if 'user_id' not in session or session['role'] not in ['admin', 'super_admin']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if USE_SQLITE:
            c.execute("DELETE FROM forms WHERE id = ? AND status = ?", (form_id, 'Submitted'))
        else:
            c.execute("DELETE FROM forms WHERE id = %s AND status = %s", (form_id, 'Submitted'))
        if c.rowcount == 0:
            flash('Request not found or already processed.', 'danger')
        else:
            conn.commit()
            flash('Request rejected and removed.', 'success')
            log_action(session['user_id'], f"Rejected request {form_id}")
        return redirect(url_for('manage_requests'))
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('manage_requests'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/close_form/<int:form_id>')
def close_form(form_id):
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if USE_SQLITE:
            c.execute("UPDATE forms SET status = ? WHERE id = ? AND status = ?", ('Closed', form_id, 'Acknowledged'))
        else:
            c.execute("UPDATE forms SET status = %s WHERE id = %s AND status = %s", ('Closed', form_id, 'Acknowledged'))
        if c.rowcount == 0:
            flash('Form not found or not ready to close.', 'danger')
        else:
            conn.commit()
            flash('Form closed successfully!', 'success')
            log_action(session['user_id'], f"Closed form {form_id}")
        return redirect(url_for('manage_requests'))
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('manage_requests'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/all_forms')
def all_forms():
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        # Fetch all forms with usernames
        c.execute("SELECT f.*, u.username FROM forms f JOIN users u ON f.user_id = u.id ORDER BY f.created_at DESC")
        forms = c.fetchall()
        
        # Fetch all relevant logs in one query to reduce database calls
        form_ids = [form['id'] for form in forms]
        if USE_SQLITE:
            c.execute("SELECT * FROM logs WHERE action LIKE '%request%' OR action LIKE '%form%'")
        else:
            c.execute("SELECT * FROM logs WHERE action ILIKE '%request%' OR action ILIKE '%form%'")
        logs = c.fetchall()
        
        # Process logs to extract timestamps
        logs_dict = {}
        for log in logs:
            log_action = log['action']
            for form_id in form_ids:
                if str(form_id) in log_action:
                    if form_id not in logs_dict:
                        logs_dict[form_id] = {'approved_at': 'N/A', 'acknowledged_at': 'N/A'}
                    if 'Approved' in log_action:
                        logs_dict[form_id]['approved_at'] = log['timestamp']
                    elif 'Acknowledged' in log_action:
                        logs_dict[form_id]['acknowledged_at'] = log['timestamp']
        
        # Build form details with timestamps
        form_details = []
        for form in forms:
            form_dict = dict(form)
            form_id = form['id']
            form_dict['submitted_at'] = form['created_at']
            form_dict['approved_at'] = logs_dict.get(form_id, {}).get('approved_at', 'N/A')
            form_dict['acknowledged_at'] = logs_dict.get(form_id, {}).get('acknowledged_at', 'N/A') if form['acknowledged'] == 1 else 'N/A'
            form_details.append(form_dict)
        
        return render_template('all_forms.html', forms=form_details)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/approved_requests')
def approved_requests():
    if 'user_id' not in session:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if session['role'] == 'dummy_user':
            if USE_SQLITE:
                c.execute("SELECT f.*, u.username FROM forms f JOIN users u ON f.user_id = u.id WHERE f.assigned_dummy_user_id = ? AND f.status = ?",
                          (session['user_id'], 'Approved'))
            else:
                c.execute("SELECT f.*, u.username FROM forms f JOIN users u ON f.user_id = u.id WHERE f.assigned_dummy_user_id = %s AND f.status = %s",
                          (session['user_id'], 'Approved'))
        else:
            if USE_SQLITE:
                c.execute("SELECT f.*, u.username FROM forms f JOIN users u ON f.user_id = u.id WHERE f.user_id = ? AND f.status = ?",
                          (session['user_id'], 'Approved'))
            else:
                c.execute("SELECT f.*, u.username FROM forms f JOIN users u ON f.user_id = u.id WHERE f.user_id = %s AND f.status = %s",
                          (session['user_id'], 'Approved'))
        forms = c.fetchall()
        return render_template('approved_requests.html', forms=forms)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/acknowledge_requests')
def acknowledge_requests():
    if 'user_id' not in session or session['role'] in ['admin', 'super_admin', 'dummy_user']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if USE_SQLITE:
            c.execute("SELECT f.*, u.username FROM forms f JOIN users u ON f.user_id = u.id WHERE f.user_id = ? AND f.status = ? AND f.acknowledged = 0",
                      (session['user_id'], 'Approved'))
        else:
            c.execute("SELECT f.*, u.username FROM forms f JOIN users u ON f.user_id = u.id WHERE f.user_id = %s AND f.status = %s AND f.acknowledged = 0",
                      (session['user_id'], 'Approved'))
        forms = c.fetchall()
        return render_template('acknowledge_requests.html', forms=forms)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/acknowledge/<int:form_id>')
def acknowledge(form_id):
    if 'user_id' not in session or session['role'] in ['admin', 'super_admin', 'dummy_user']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if USE_SQLITE:
            c.execute("UPDATE forms SET acknowledged = 1, status = ? WHERE id = ? AND user_id = ?", ('Acknowledged', form_id, session['user_id']))
        else:
            c.execute("UPDATE forms SET acknowledged = 1, status = %s WHERE id = %s AND user_id = %s", ('Acknowledged', form_id, session['user_id']))
        if c.rowcount == 0:
            flash('Form not found or already acknowledged.', 'danger')
        else:
            conn.commit()
            flash('Form acknowledged successfully!', 'success')
            log_action(session['user_id'], f"Acknowledged form {form_id}")
        return redirect(url_for('acknowledge_requests'))
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('acknowledge_requests'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            if USE_SQLITE:
                c.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],))
            else:
                c.execute("SELECT password FROM users WHERE id = %s", (session['user_id'],))
            user = c.fetchone()
            if user and bcrypt.checkpw(old_password.encode('utf-8'), user['password'].encode('utf-8')):
                if USE_SQLITE:
                    c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_new_password, session['user_id']))
                else:
                    c.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_new_password, session['user_id']))
                conn.commit()
                flash('Password changed successfully!', 'success')
                log_action(session['user_id'], "Changed password")
                return redirect(url_for('dashboard'))
            else:
                flash('Old password is incorrect.', 'danger')
                return redirect(url_for('change_password'))
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
            return redirect(url_for('change_password'))
        finally:
            if conn is not None:
                conn.close()
    return render_template('change_password.html')

@app.route('/user_requests')
def user_requests():
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, username, email, created_at FROM users WHERE approved = 0")
        pending_users = c.fetchall()
        return render_template('user_requests.html', pending_users=pending_users)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/approve_user/<int:user_id>')
def approve_user(user_id):
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        role = request.args.get('role', 'user')
        if USE_SQLITE:
            c.execute("UPDATE users SET approved = 1, role = ? WHERE id = ?", (role, user_id))
        else:
            c.execute("UPDATE users SET approved = 1, role = %s WHERE id = %s", (role, user_id))
        conn.commit()
        flash('User approved successfully!', 'success')
        log_action(session['user_id'], f"Approved user {user_id} as {role}")
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
    finally:
        if conn is not None:
            conn.close()
    return redirect(url_for('user_requests'))

@app.route('/reject_user/<int:user_id>')
def reject_user(user_id):
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if USE_SQLITE:
            c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        else:
            c.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        flash('User rejected and removed.', 'success')
        log_action(session['user_id'], f"Rejected user {user_id}")
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
    finally:
        if conn is not None:
            conn.close()
    return redirect(url_for('user_requests'))

@app.route('/manage_dummy_users', methods=['GET', 'POST'])
def manage_dummy_users():
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        email = request.form['email']
        tz = pytz.timezone('Asia/Kolkata')
        created_at = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            if USE_SQLITE:
                c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (?, ?, ?, ?, ?, ?)",
                          (username, hashed_password, 'dummy_user', 1, created_at, email))
            else:
                c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (%s, %s, %s, %s, %s, %s)",
                          (username, hashed_password, 'dummy_user', 1, created_at, email))
            conn.commit()
            flash('Dummy user added successfully!', 'success')
            log_action(session['user_id'], f"Added dummy user {username}")
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
        finally:
            if conn is not None:
                conn.close()
        return redirect(url_for('manage_dummy_users'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE role = 'dummy_user'")
        dummy_users = c.fetchall()
        return render_template('manage_dummy_users.html', dummy_users=dummy_users)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/edit_dummy_user/<int:user_id>', methods=['GET', 'POST'])
def edit_dummy_user(user_id):
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            if USE_SQLITE:
                c.execute("UPDATE users SET username = ?, email = ? WHERE id = ? AND role = ?",
                          (username, email, user_id, 'dummy_user'))
            else:
                c.execute("UPDATE users SET username = %s, email = %s WHERE id = %s AND role = %s",
                          (username, email, user_id, 'dummy_user'))
            conn.commit()
            flash('Dummy user updated successfully!', 'success')
            log_action(session['user_id'], f"Updated dummy user {user_id}")
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
        finally:
            if conn is not None:
                conn.close()
        return redirect(url_for('manage_dummy_users'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if USE_SQLITE:
            c.execute("SELECT * FROM users WHERE id = ? AND role = ?", (user_id, 'dummy_user'))
        else:
            c.execute("SELECT * FROM users WHERE id = %s AND role = %s", (user_id, 'dummy_user'))
        user = c.fetchone()
        if not user:
            flash('Dummy user not found.', 'danger')
            return redirect(url_for('manage_dummy_users'))
        return render_template('edit_dummy_user.html', user=user)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('manage_dummy_users'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/delete_dummy_user/<int:user_id>')
def delete_dummy_user(user_id):
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if USE_SQLITE:
            c.execute("DELETE FROM users WHERE id = ? AND role = ?", (user_id, 'dummy_user'))
        else:
            c.execute("DELETE FROM users WHERE id = %s AND role = %s", (user_id, 'dummy_user'))
        conn.commit()
        flash('Dummy user deleted successfully!', 'success')
        log_action(session['user_id'], f"Deleted dummy user {user_id}")
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
    finally:
        if conn is not None:
            conn.close()
    return redirect(url_for('manage_dummy_users'))

@app.route('/manage_questions', methods=['GET', 'POST'])
def manage_questions():
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        question_text = request.form['question_text']
        question_type = request.form['question_type']
        options = request.form.get('options', '')
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT MAX(position) as position FROM questions")
            max_position = c.fetchone()['position']
            position = (max_position or 0) + 1
            if USE_SQLITE:
                c.execute("INSERT INTO questions (question_text, question_type, options, position) VALUES (?, ?, ?, ?)",
                          (question_text, question_type, options, position))
            else:
                c.execute("INSERT INTO questions (question_text, question_type, options, position) VALUES (%s, %s, %s, %s)",
                          (question_text, question_type, options, position))
            conn.commit()
            flash('Question added successfully!', 'success')
            log_action(session['user_id'], f"Added question: {question_text}")
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
        finally:
            if conn is not None:
                conn.close()
        return redirect(url_for('manage_questions'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM questions ORDER BY position")
        questions = c.fetchall()
        return render_template('manage_questions.html', questions=questions)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
def edit_question(question_id):
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        question_text = request.form['question_text']
        question_type = request.form['question_type']
        options = request.form.get('options', '')
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            if USE_SQLITE:
                c.execute("UPDATE questions SET question_text = ?, question_type = ?, options = ? WHERE id = ?",
                          (question_text, question_type, options, question_id))
            else:
                c.execute("UPDATE questions SET question_text = %s, question_type = %s, options = %s WHERE id = %s",
                          (question_text, question_type, options, question_id))
            conn.commit()
            flash('Question updated successfully!', 'success')
            log_action(session['user_id'], f"Updated question {question_id}")
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
        finally:
            if conn is not None:
                conn.close()
        return redirect(url_for('manage_questions'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if USE_SQLITE:
            c.execute("SELECT * FROM questions WHERE id = ?", (question_id,))
        else:
            c.execute("SELECT * FROM questions WHERE id = %s", (question_id,))
        question = c.fetchone()
        if not question:
            flash('Question not found.', 'danger')
            return redirect(url_for('manage_questions'))
        return render_template('edit_question.html', question=question)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('manage_questions'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/delete_question/<int:question_id>')
def delete_question(question_id):
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if USE_SQLITE:
            c.execute("DELETE FROM questions WHERE id = ?", (question_id,))
        else:
            c.execute("DELETE FROM questions WHERE id = %s", (question_id,))
        conn.commit()
        flash('Question deleted successfully!', 'success')
        log_action(session['user_id'], f"Deleted question {question_id}")
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
    finally:
        if conn is not None:
            conn.close()
    return redirect(url_for('manage_questions'))

# Decorator to restrict routes to super admins
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'super_admin':
            flash('Access denied: Super admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/download_logs')
@super_admin_required
def download_logs():
    # Query all logs from the database
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT l.*, u.username FROM logs l JOIN users u ON l.user_id = u.id ORDER BY l.timestamp DESC")
        logs = c.fetchall()
        
        # Create a CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write CSV headers
        writer.writerow(['Username', 'Action', 'Timestamp'])
        
        # Write log data
        for log in logs:
            writer.writerow([log['username'], log['action'], log['timestamp']])
        
        # Prepare the response
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=log_sheet.csv'
        response.headers['Content-type'] = 'text/csv'
        return response
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('view_logs'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/download_form_summary')
@super_admin_required
def download_form_summary():
    # Query all forms from the database
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT f.*, u.username FROM forms f JOIN users u ON f.user_id = u.id ORDER BY f.created_at DESC")
        forms = c.fetchall()
        
        # Fetch all relevant logs in one query to reduce database calls
        form_ids = [form['id'] for form in forms]
        if USE_SQLITE:
            c.execute("SELECT * FROM logs WHERE action LIKE '%request%' OR action LIKE '%form%'")
        else:
            c.execute("SELECT * FROM logs WHERE action ILIKE '%request%' OR action ILIKE '%form%'")
        logs = c.fetchall()
        
        # Process logs to extract timestamps
        logs_dict = {}
        for log in logs:
            log_action = log['action']
            for form_id in form_ids:
                if str(form_id) in log_action:
                    if form_id not in logs_dict:
                        logs_dict[form_id] = {'approved_at': 'N/A', 'acknowledged_at': 'N/A'}
                    if 'Approved' in log_action:
                        logs_dict[form_id]['approved_at'] = log['timestamp']
                    elif 'Acknowledged' in log_action:
                        logs_dict[form_id]['acknowledged_at'] = log['timestamp']
        
        # Create a CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write CSV headers
        writer.writerow(['Request ID', 'Username', 'Status', 'Submitted At', 'Approved At', 'Approved ID', 'Acknowledged At'])
        
        # Write form data with timestamps
        for form in forms:
            form_id = form['id']
            submitted_at = form['created_at']
            approved_at = logs_dict.get(form_id, {}).get('approved_at', 'N/A')
            acknowledged_at = logs_dict.get(form_id, {}).get('acknowledged_at', 'N/A') if form['acknowledged'] == 1 else 'N/A'
            
            writer.writerow([
                form['request_id'],
                form['username'],
                form['status'],
                submitted_at,
                approved_at,
                form['approved_id'] or 'N/A',
                acknowledged_at
            ])
        
        # Prepare the response
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=form_summary.csv'
        response.headers['Content-type'] = 'text/csv'
        return response
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('view_logs'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/view_logs')
def view_logs():
    if 'user_id' not in session or session['role'] not in ['admin', 'super_admin']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT l.*, u.username FROM logs l JOIN users u ON l.user_id = u.id ORDER BY l.timestamp DESC")
        logs = c.fetchall()
        return render_template('view_logs.html', logs=logs)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn is not None:
            conn.close()

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    username = session.get('username', 'Unknown')
    session.clear()
    flash('You have been logged out.', 'success')
    if user_id:
        log_action(user_id, f"User {username} logged out")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)