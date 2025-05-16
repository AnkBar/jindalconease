import sqlite3
import hashlib
import uuid
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, session, flash, send_file
from functools import wraps
import pytz
import smtplib
from email.mime.text import MIMEText
import csv
import io
import time

app = Flask(__name__)
app.secret_key = 'your_secure_secret_key'  # Replace with a secure key for production

# Email configuration (update with your SMTP details)
EMAIL_ADDRESS = 'your_email@gmail.com'  # Replace with your email
EMAIL_PASSWORD = 'your_app_password'    # Replace with your app-specific password
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# Database initialization with timeout
def get_db_connection():
    conn = sqlite3.connect('approval_system.db', timeout=10)
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
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
        form_id TEXT UNIQUE,
        answers TEXT,
        status TEXT,
        admin_id INTEGER,
        approval_id TEXT,
        acknowledged INTEGER DEFAULT 0,
        created_at TEXT,
        approved_at TEXT,
        acknowledged_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(admin_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        question_text TEXT,
        question_type TEXT,
        options TEXT,
        form_image TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        timestamp TEXT,
        details TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS dummy_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        task TEXT,
        assigned_by INTEGER,
        created_at TEXT,
        FOREIGN KEY(assigned_by) REFERENCES users(id)
    )''')
    # Insert default super admin
    c.execute("SELECT * FROM users WHERE role='super_admin'")
    if not c.fetchone():
        hashed_password = hashlib.sha256('superadmin123'.encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (?, ?, ?, ?, ?, ?)",
                  ('superadmin', hashed_password, 'super_admin', 1, datetime.now(pytz.timezone('Asia/Kolkata')).isoformat(), 'superadmin@example.com'))
    # Insert default admin
    c.execute("SELECT * FROM users WHERE username='admin' AND role='admin'")
    if not c.fetchone():
        hashed_password = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (?, ?, ?, ?, ?, ?)",
                  ('admin', hashed_password, 'admin', 1, datetime.now(pytz.timezone('Asia/Kolkata')).isoformat(), 'admin@example.com'))
    # Insert default questions if none exist
    c.execute("SELECT * FROM questions")
    if not c.fetchone():
        default_questions = [
            ('What is your department?', 'dropdown', 'HR,IT,Finance,Operations', ''),
            ('What is your role?', 'dropdown', 'Employee,Manager,Contractor', ''),
            ('What is the project type?', 'dropdown', 'Internal,Client,Research', ''),
            ('What is the priority level?', 'dropdown', 'Low,Medium,High', ''),
            ('What is the project phase?', 'dropdown', 'Planning,Execution,Testing,Completion', ''),
            ('What is the resource need?', 'dropdown', 'Team,Equipment,Budget', ''),
            ('What is the risk level?', 'dropdown', 'Low,Medium,High', ''),
            ('What is the compliance requirement?', 'dropdown', 'Yes,No', ''),
            ('What is the stakeholder involvement?', 'dropdown', 'High,Medium,Low', ''),
            ('What is the expected outcome?', 'dropdown', 'Success,Partial,Failure', ''),
            ('Describe the project details', 'text', '', ''),
            ('Additional comments', 'text', '', '')
        ]
        c.executemany("INSERT INTO questions (question_text, question_type, options, form_image) VALUES (?, ?, ?, ?)", default_questions)
    conn.commit()
    conn.close()

init_db()

# Send email notification
def send_email(to_email, subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
    except Exception as e:
        print(f"Failed to send email: {e}")

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        conn.close()
        if user and user[0] not in ['admin', 'super_admin']:
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Super Admin required decorator
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        conn.close()
        if user and user[0] != 'super_admin':
            flash('Super Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Log action
def log_action(user_id, action, details):
    conn = get_db_connection()
    c = conn.cursor()
    timestamp = datetime.now(pytz.timezone('Asia/Kolkata')).isoformat()
    c.execute("INSERT INTO logs (user_id, action, timestamp, details) VALUES (?, ?, ?, ?)",
              (user_id, action, timestamp, details))
    conn.commit()
    conn.close()

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, role, approved, email FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()
        if user and user[2] == 1:
            session['user_id'] = user[0]
            session['role'] = user[1]
            log_action(user[0], 'login', f'User {username} logged in')
            send_email(user[3], 'Login Notification', f'You logged into the Approval System at {datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")} IST.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials or user not approved.', 'error')
    return render_template('login.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        email = request.form['email']
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (?, ?, ?, ?, ?, ?)",
                      (username, password, 'pending', 0, datetime.now(pytz.timezone('Asia/Kolkata')).isoformat(), email))
            conn.commit()
            log_action(None, 'signup', f'User {username} signed up')
            c.execute("SELECT email FROM users WHERE role = 'super_admin'")
            super_admin_emails = [row[0] for row in c.fetchall()]
            for super_admin_email in super_admin_emails:
                send_email(super_admin_email, 'New User Signup', f'User {username} has signed up and is awaiting approval.')
            flash('Signup successful! Awaiting Super Admin approval.', 'success')
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
        finally:
            conn.close()
        return redirect(url_for('login'))
    return render_template('signup.html')

# User requests route (Super Admin only)
@app.route('/user_requests', methods=['GET'])
@super_admin_required
def user_requests():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, role, approved, email, created_at FROM users WHERE role != 'super_admin'")
    users = c.fetchall()
    conn.close()
    return render_template('user_requests.html', users=users)

# Approve user with role (Super Admin only)
@app.route('/approve_user/<int:user_id>', methods=['POST'])
@super_admin_required
def approve_user(user_id):
    role = request.form['role']
    if role not in ['admin', 'user']:
        flash('Invalid role selected.', 'error')
        return redirect(url_for('user_requests'))

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET role = ?, approved = 1 WHERE id = ?", (role, user_id))
        c.execute("SELECT email, username FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        conn.commit()
        log_action(session['user_id'], 'user_approval', f'User ID {user_id} approved as {role}')
        send_email(user[0], 'Account Approved', f'Your account {user[1]} has been approved as a {role}.')
        flash(f'User {user[1]} approved as {role}.', 'success')
    except sqlite3.OperationalError as e:
        flash(f'Database error: {str(e)}. Please try again.', 'error')
    finally:
        conn.close()
    return redirect(url_for('user_requests'))

# Reject user (Super Admin only)
@app.route('/reject_user/<int:user_id>', methods=['POST'])
@super_admin_required
def reject_user(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT email, username FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        if user:
            c.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            log_action(session['user_id'], 'user_rejection', f'User ID {user_id} rejected')
            send_email(user[0], 'Account Rejected', f'Your account {user[1]} has been rejected by the Super Admin.')
            flash(f'User {user[1]} rejected.', 'success')
        else:
            flash('User not found.', 'error')
    except sqlite3.OperationalError as e:
        flash(f'Database error: {str(e)}. Please try again.', 'error')
    finally:
        conn.close()
    return redirect(url_for('user_requests'))

# Change user role (Super Admin only)
@app.route('/change_role/<int:user_id>', methods=['POST'])
@super_admin_required
def change_role(user_id):
    new_role = request.form['new_role']
    if new_role not in ['admin', 'user']:
        flash('Invalid role selected.', 'error')
        return redirect(url_for('user_requests'))

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        c.execute("SELECT email, username FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        conn.commit()
        log_action(session['user_id'], 'role_change', f'User ID {user_id} role changed to {new_role}')
        send_email(user[0], 'Role Updated', f'Your role has been updated to {new_role} by the Super Admin.')
        flash(f'User {user[1]} role updated to {new_role}.', 'success')
    except sqlite3.OperationalError as e:
        flash(f'Database error: {str(e)}. Please try again.', 'error')
    finally:
        conn.close()
    return redirect(url_for('user_requests'))

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    c = conn.cursor()
    user_id = session['user_id']
    role = session['role']
    
    # Fetch request stats
    c.execute("SELECT COUNT(*) FROM forms WHERE user_id = ?", (user_id,))
    total_requests = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM forms WHERE user_id = ? AND status = 'approved'", (user_id,))
    approved_requests = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM forms WHERE user_id = ? AND acknowledged = 1", (user_id,))
    acknowledged_requests = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM forms WHERE user_id = ? AND status = 'rejected'", (user_id,))
    rejected_requests = c.fetchone()[0]
    
    stats = f"{total_requests}/{approved_requests}/{acknowledged_requests}/{rejected_requests}"
    
    if role in ['admin', 'super_admin']:
        c.execute("SELECT f.id, f.form_id, u.username, f.status, f.created_at FROM forms f JOIN users u ON f.user_id = u.id")
        requests = c.fetchall()
        c.execute("SELECT id, name, task, created_at FROM dummy_users WHERE assigned_by = ?", (user_id,))
        dummy_users = c.fetchall()
    else:
        c.execute("SELECT id, form_id, status, created_at, acknowledged FROM forms WHERE user_id = ?", (user_id,))
        requests = c.fetchall()
        dummy_users = []
    
    conn.close()
    return render_template('dashboard.html', role=role, requests=requests, stats=stats, dummy_users=dummy_users)

# Form submission route
@app.route('/submit_form', methods=['GET', 'POST'])
@login_required
def submit_form():
    if session['role'] in ['admin', 'super_admin']:
        flash('Admins cannot submit forms.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM questions")
    questions = c.fetchall()
    
    if request.method == 'POST':
        answers = {}
        for q in questions:
            q_id = str(q[0])
            answers[q_id] = request.form.get(q_id, '')
        
        form_id = f"U{uuid.uuid4().hex[:8]}"
        try:
            c.execute("INSERT INTO forms (user_id, form_id, answers, status, created_at) VALUES (?, ?, ?, ?, ?)",
                      (session['user_id'], form_id, str(answers), 'pending', datetime.now(pytz.timezone('Asia/Kolkata')).isoformat()))
            conn.commit()
            log_action(session['user_id'], 'form_submission', f'Form {form_id} submitted')
            c.execute("SELECT email FROM users WHERE id = ?", (session['user_id'],))
            user_email = c.fetchone()[0]
            c.execute("SELECT email FROM users WHERE role IN ('admin', 'super_admin')")
            admin_emails = [row[0] for row in c.fetchall()]
            send_email(user_email, 'Form Submission', f'Your form {form_id} has been submitted.')
            for admin_email in admin_emails:
                send_email(admin_email, 'New Form Submission', f'Form {form_id} has been submitted by user ID {session["user_id"]}.')
            flash(f'Form {form_id} submitted successfully.', 'success')
        except sqlite3.OperationalError as e:
            flash(f'Database error: {str(e)}. Please try again.', 'error')
        finally:
            conn.close()
        return redirect(url_for('dashboard'))
    
    conn.close()
    return render_template('submit_form.html', questions=questions)

# View form details
@app.route('/view_form/<form_id>')
@login_required
def view_form(form_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT f.*, u.username AS user_name, a.username AS admin_name FROM forms f JOIN users u ON f.user_id = u.id LEFT JOIN users a ON f.admin_id = a.id WHERE f.form_id = ?", (form_id,))
    form = c.fetchone()
    c.execute("SELECT * FROM questions")
    questions = c.fetchall()
    conn.close()
    
    if not form:
        flash('Form not found.', 'error')
        return redirect(url_for('dashboard'))
    
    if session['role'] not in ['admin', 'super_admin'] and form[1] != session['user_id']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('view_form.html', form=form, questions=questions)

# Acknowledge form
@app.route('/acknowledge_form/<form_id>', methods=['POST'])
@login_required
def acknowledge_form(form_id):
    if session['role'] in ['admin', 'super_admin']:
        flash('Admins cannot acknowledge forms.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("UPDATE forms SET acknowledged = 1, acknowledged_at = ? WHERE form_id = ? AND user_id = ?",
                  (datetime.now(pytz.timezone('Asia/Kolkata')).isoformat(), form_id, session['user_id']))
        conn.commit()
        log_action(session['user_id'], 'form_acknowledgement', f'Form {form_id} acknowledged')
        c.execute("SELECT email FROM users WHERE id = ?", (session['user_id'],))
        user_email = c.fetchone()[0]
        send_email(user_email, 'Form Acknowledged', f'You have acknowledged form {form_id}.')
        flash(f'Form {form_id} acknowledged.', 'success')
    except sqlite3.OperationalError as e:
        flash(f'Database error: {str(e)}. Please try again.', 'error')
    finally:
        conn.close()
    return redirect(url_for('dashboard'))

# Admin approve/reject/modify form
@app.route('/manage_form/<form_id>', methods=['POST'])
@admin_required
def manage_form(form_id):
    action = request.form['action']
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT user_id, answers FROM forms WHERE form_id = ?", (form_id,))
        form = c.fetchone()
        
        if action == 'approve':
            approval_id = f"A{uuid.uuid4().hex[:8]}"
            c.execute("UPDATE forms SET status = 'approved', admin_id = ?, approval_id = ?, approved_at = ? WHERE form_id = ?",
                      (session['user_id'], approval_id, datetime.now(pytz.timezone('Asia/Kolkata')).isoformat(), form_id))
            conn.commit()
            log_action(session['user_id'], 'form_approval', f'Form {form_id} approved with ID {approval_id}')
            c.execute("SELECT email FROM users WHERE id = ?", (form[0],))
            user_email = c.fetchone()[0]
            send_email(user_email, 'Form Approved', f'Your form {form_id} has been approved with ID {approval_id}.')
            flash(f'Form {form_id} approved with ID {approval_id}.', 'success')
        elif action == 'reject':
            c.execute("UPDATE forms SET status = 'rejected', admin_id = ?, approved_at = ? WHERE form_id = ?",
                      (session['user_id'], datetime.now(pytz.timezone('Asia/Kolkata')).isoformat(), form_id))
            conn.commit()
            log_action(session['user_id'], 'form_rejection', f'Form {form_id} rejected')
            c.execute("SELECT email FROM users WHERE id = ?", (form[0],))
            user_email = c.fetchone()[0]
            send_email(user_email, 'Form Rejected', f'Your form {form_id} has been rejected.')
            flash(f'Form {form_id} rejected.', 'success')
        elif action == 'modify':
            answers = {}
            c.execute("SELECT * FROM questions")
            questions = c.fetchall()
            for q in questions:
                q_id = str(q[0])
                answers[q_id] = request.form.get(q_id, '')
            c.execute("UPDATE forms SET answers = ?, status = 'modified', admin_id = ?, approved_at = ? WHERE form_id = ?",
                      (str(answers), session['user_id'], datetime.now(pytz.timezone('Asia/Kolkata')).isoformat(), form_id))
            conn.commit()
            log_action(session['user_id'], 'form_modification', f'Form {form_id} modified')
            c.execute("SELECT email FROM users WHERE id = ?", (form[0],))
            user_email = c.fetchone()[0]
            send_email(user_email, 'Form Modified', f'Your form {form_id} has been modified by an admin.')
            flash(f'Form {form_id} modified.', 'success')
    except sqlite3.OperationalError as e:
        flash(f'Database error: {str(e)}. Please try again.', 'error')
    finally:
        conn.close()
    return redirect(url_for('dashboard'))

# Manage admins (Super Admin only)
@app.route('/manage_admins', methods=['GET', 'POST'])
@super_admin_required
def manage_admins():
    conn = get_db_connection()
    c = conn.cursor()
    
    if request.method == 'POST':
        action = request.form['action']
        user_id = request.form.get('user_id')
        try:
            if action == 'create':
                username = request.form['username']
                password = hashlib.sha256(request.form['password'].encode()).hexdigest()
                email = request.form['email']
                c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (?, ?, ?, ?, ?, ?)",
                          (username, password, 'admin', 1, datetime.now(pytz.timezone('Asia/Kolkata')).isoformat(), email))
                conn.commit()
                log_action(session['user_id'], 'admin_create', f'Admin {username} created')
                send_email(email, 'Admin Account Created', f'Your admin account {username} has been created.')
                flash('Admin created.', 'success')
            elif action == 'delete' and user_id:
                c.execute("DELETE FROM users WHERE id = ? AND role = 'admin'", (user_id,))
                conn.commit()
                log_action(session['user_id'], 'admin_delete', f'Admin ID {user_id} deleted')
                flash('Admin deleted.', 'success')
        except sqlite3.OperationalError as e:
            flash(f'Database error: {str(e)}. Please try again.', 'error')
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
        finally:
            conn.close()
    
    c.execute("SELECT id, username, approved, email FROM users WHERE role = 'admin'")
    admins = c.fetchall()
    conn.close()
    return render_template('manage_admins.html', admins=admins)

# Manage questions
@app.route('/manage_questions', methods=['GET', 'POST'])
@admin_required
def manage_questions():
    conn = get_db_connection()
    c = conn.cursor()
    
    if request.method == 'POST':
        question_id = request.form.get('question_id')
        question_text = request.form['question_text']
        question_type = request.form['question_type']
        options = request.form.get('options', '')
        form_image = request.form.get('form_image', '')
        
        try:
            if question_id:  # Update existing question
                c.execute("UPDATE questions SET question_text = ?, question_type = ?, options = ?, form_image = ? WHERE id = ?",
                          (question_text, question_type, options, form_image, question_id))
                conn.commit()
                log_action(session['user_id'], 'question_update', f'Question ID {question_id} updated')
                flash('Question updated.', 'success')
            else:  # Add new question
                c.execute("INSERT INTO questions (question_text, question_type, options, form_image) VALUES (?, ?, ?, ?)",
                          (question_text, question_type, options, form_image))
                conn.commit()
                log_action(session['user_id'], 'question_add', f'New question added: {question_text}')
                flash('Question added.', 'success')
        except sqlite3.OperationalError as e:
            flash(f'Database error: {str(e)}. Please try again.', 'error')
        finally:
            conn.close()
    
    c.execute("SELECT * FROM questions")
    questions = c.fetchall()
    conn.close()
    return render_template('manage_questions.html', questions=questions)

# Manage dummy users
@app.route('/manage_dummy_users', methods=['GET', 'POST'])
@admin_required
def manage_dummy_users():
    conn = get_db_connection()
    c = conn.cursor()
    
    if request.method == 'POST':
        name = request.form['name']
        task = request.form['task']
        try:
            c.execute("INSERT INTO dummy_users (name, task, assigned_by, created_at) VALUES (?, ?, ?, ?)",
                      (name, task, session['user_id'], datetime.now(pytz.timezone('Asia/Kolkata')).isoformat()))
            conn.commit()
            log_action(session['user_id'], 'dummy_user_add', f'Dummy user {name} added with task {task}')
            flash('Dummy user added.', 'success')
        except sqlite3.OperationalError as e:
            flash(f'Database error: {str(e)}. Please try again.', 'error')
        finally:
            conn.close()
    
    c.execute("SELECT id, name, task, created_at FROM dummy_users WHERE assigned_by = ?", (session['user_id'],))
    dummy_users = c.fetchall()
    conn.close()
    return render_template('manage_dummy_users.html', dummy_users=dummy_users)

# Export forms as CSV
@app.route('/export_forms')
@admin_required
def export_forms():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT f.form_id, u.username, f.status, f.created_at, f.approved_at, f.acknowledged, f.acknowledged_at, f.answers, a.username AS admin_name FROM forms f JOIN users u ON f.user_id = u.id LEFT JOIN users a ON f.admin_id = a.id")
    forms = c.fetchall()
    c.execute("SELECT id, question_text FROM questions")
    questions = c.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    headers = ['Form ID', 'User', 'Status', 'Created At', 'Approved At', 'Acknowledged', 'Acknowledged At', 'Admin']
    headers.extend([q[1] for q in questions])
    writer.writerow(headers)
    
    for form in forms:
        answers = eval(form[7])
        row = [form[0], form[1], form[2], form[3], form[4], 'Yes' if form[5] else 'No', form[6], form[8]]
        row.extend([answers.get(str(q[0]), '') for q in questions])
        writer.writerow(row)
    
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='forms_export.csv')

# Export logs as CSV
@app.route('/export_logs')
@admin_required
def export_logs():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT l.*, u.username FROM logs l LEFT JOIN users u ON l.user_id = u.id ORDER BY l.timestamp DESC")
    logs = c.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['User', 'Action', 'Timestamp', 'Details'])
    
    for log in logs:
        writer.writerow([log[5] or 'System', log[2], log[3], log[4]])
    
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='logs_export.csv')

# View logs
@app.route('/view_logs')
@admin_required
def view_logs():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT l.*, u.username FROM logs l LEFT JOIN users u ON l.user_id = u.id ORDER BY l.timestamp DESC")
    logs = c.fetchall()
    conn.close()
    return render_template('view_logs.html', logs=logs)

# Logout
@app.route('/logout')
@login_required
def logout():
    user_id = session['user_id']
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    user_email = c.fetchone()[0]
    conn.close()
    session.pop('user_id', None)
    session.pop('role', None)
    log_action(user_id, 'logout', 'User logged out')
    send_email(user_email, 'Logout Notification', f'You logged out of the Approval System at {datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")} IST.')
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)  # Enable debug mode