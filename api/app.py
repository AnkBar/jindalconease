import os
import json
from flask import Flask, request, session, flash, redirect, url_for, render_template, jsonify
from datetime import datetime
import pytz
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key-fallback")  # Set in vercel.json or Vercel dashboard

# Database connection
def get_db_connection():
    conn = psycopg2.connect(
        os.getenv("POSTGRES_URL"),
        cursor_factory=RealDictCursor
    )
    return conn

def init_db():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        # Users table
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            approved INTEGER DEFAULT 0,
            created_at TEXT,
            email TEXT
        )''')
        # Forms table
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
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        # Questions table
        c.execute('''CREATE TABLE IF NOT EXISTS questions (
            id SERIAL PRIMARY KEY,
            question_text TEXT,
            question_type TEXT,
            options TEXT,
            position INTEGER
        )''')
        # Logs table
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            action TEXT,
            timestamp TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        # Insert initial users for trial
        c.execute("SELECT * FROM users WHERE username = 'superadmin'")
        if not c.fetchall():
            c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (%s, %s, %s, %s, %s, %s)",
                      ('superadmin', 'superadmin123', 'super_admin', 1, '2025-05-16 13:00:00', 'superadmin@example.com'))
            c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (%s, %s, %s, %s, %s, %s)",
                      ('admin', 'admin123', 'admin', 1, '2025-05-16 13:00:00', 'admin@example.com'))
            c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (%s, %s, %s, %s, %s, %s)",
                      ('user', 'user123', 'user', 1, '2025-05-16 13:00:00', 'user@example.com'))
        conn.commit()
    except Exception as e:
        print(f"Database initialization error: {e}")
    finally:
        conn.close()

with app.app_context():
    init_db()

# Helper function to log actions
def log_action(user_id, action):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        tz = pytz.timezone('Asia/Kolkata')
        timestamp = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("INSERT INTO logs (user_id, action, timestamp) VALUES (%s, %s, %s)", (user_id, action, timestamp))
        conn.commit()
    except Exception as e:
        print(f"Logging error: {e}")
    finally:
        conn.close()

# Error handler
@app.errorhandler(Exception)
def handle_exception(e):
    print(f"Unhandled exception: {str(e)}")
    return render_template('error.html', error=str(e)), 500

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    init_db()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
            user = c.fetchone()
            if user and user['approved'] == 1:
                session['user_id'] = user['id']
                session['role'] = user['role']
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
            conn.close()
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    init_db()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        tz = pytz.timezone('Asia/Kolkata')
        created_at = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (%s, %s, %s, %s, %s, %s)",
                      (username, password, 'user', 0, created_at, email))
            conn.commit()
            flash('Sign-up successful! Please wait for approval.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('signup'))
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        try:
            conn = get_db_connection()
            c = conn.cursor()
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
            conn.close()
    return render_template('forgot_password.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT status, COUNT(*) FROM forms WHERE user_id = %s GROUP BY status", (session['user_id'],))
        stats = c.fetchall()
        stats_dict = {row['status']: row['count'] for row in stats}
        return render_template('dashboard.html', stats=stats_dict)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        conn.close()

@app.route('/raise_request', methods=['GET', 'POST'])
def raise_request():
    if 'user_id' not in session or session['role'] in ['admin', 'super_admin', 'dummy_user']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM questions ORDER BY position")
            questions = c.fetchall()
            form_data = {}
            for q in questions:
                form_data[q['question_text']] = request.form.get(q['question_text'], '')
            c.execute("SELECT COUNT(*) FROM forms")
            count = c.fetchone()['count'] + 1
            request_id = f"RR{count:05d}"
            tz = pytz.timezone('Asia/Kolkata')
            created_at = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
            c.execute("INSERT INTO forms (user_id, request_id, status, created_at, data) VALUES (%s, %s, %s, %s, %s)",
                      (session['user_id'], request_id, 'Submitted', created_at, json.dumps(form_data)))
            conn.commit()
            flash(f'Request submitted successfully! Request ID: {request_id}', 'success')
            log_action(session['user_id'], f"Submitted request {request_id}")
            return redirect(url_for('raise_request'))
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
            return redirect(url_for('raise_request'))
        finally:
            conn.close()
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
        conn.close()

@app.route('/approved_requests')
def approved_requests():
    if 'user_id' not in session:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if session['role'] == 'dummy_user':
            c.execute("SELECT * FROM forms WHERE assigned_dummy_user_id = %s AND status = 'Approved'", (session['user_id'],))
        else:
            c.execute("SELECT * FROM forms WHERE user_id = %s AND status = 'Approved'", (session['user_id'],))
        forms = c.fetchall()
        return render_template('approved_requests.html', forms=forms)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        conn.close()

@app.route('/acknowledge_requests')
def acknowledge_requests():
    if 'user_id' not in session or session['role'] in ['admin', 'super_admin', 'dummy_user']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM forms WHERE user_id = %s AND status = 'Approved' AND acknowledged = 0", (session['user_id'],))
        forms = c.fetchall()
        return render_template('acknowledge_requests.html', forms=forms)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        conn.close()

@app.route('/acknowledge/<int:form_id>')
def acknowledge(form_id):
    if 'user_id' not in session or session['role'] in ['admin', 'super_admin', 'dummy_user']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE forms SET acknowledged = 1, status = 'Acknowledged' WHERE id = %s AND user_id = %s", (form_id, session['user_id']))
        conn.commit()
        flash('Form acknowledged successfully!', 'success')
        log_action(session['user_id'], f"Acknowledged form {form_id}")
        return redirect(url_for('acknowledge_requests'))
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('acknowledge_requests'))
    finally:
        conn.close()

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE id = %s", (session['user_id'],))
            user = c.fetchone()
            if user and user['password'] == old_password:
                c.execute("UPDATE users SET password = %s WHERE id = %s", (new_password, session['user_id']))
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
            conn.close()
    return render_template('change_password.html')

@app.route('/user_requests')
def user_requests():
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
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
        conn.close()

@app.route('/approve_user/<int:user_id>')
def approve_user(user_id):
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    try:
        conn = get_db_connection()
        c = conn.cursor()
        role = request.args.get('role', 'user')
        c.execute("UPDATE users SET approved = 1, role = %s WHERE id = %s", (role, user_id))
        conn.commit()
        flash('User approved successfully!', 'success')
        log_action(session['user_id'], f"Approved user {user_id} as {role}")
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('user_requests'))

@app.route('/reject_user/<int:user_id>')
def reject_user(user_id):
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        flash('User rejected and removed.', 'success')
        log_action(session['user_id'], f"Rejected user {user_id}")
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
    finally:
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
        email = request.form['email']
        tz = pytz.timezone('Asia/Kolkata')
        created_at = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, role, approved, created_at, email) VALUES (%s, %s, %s, %s, %s, %s)",
                      (username, password, 'dummy_user', 1, created_at, email))
            conn.commit()
            flash('Dummy user added successfully!', 'success')
            log_action(session['user_id'], f"Added dummy user {username}")
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
        finally:
            conn.close()
        return redirect(url_for('manage_dummy_users'))
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
        conn.close()

@app.route('/manage_questions', methods=['GET', 'POST'])
def manage_questions():
    if 'user_id' not in session or session['role'] != 'super_admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        question_text = request.form['question_text']
        question_type = request.form['question_type']
        options = request.form.get('options', '')
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT MAX(position) FROM questions")
            max_position = c.fetchone()['position']
            position = (max_position or 0) + 1
            c.execute("INSERT INTO questions (question_text, question_type, options, position) VALUES (%s, %s, %s, %s)",
                      (question_text, question_type, options, position))
            conn.commit()
            flash('Question added successfully!', 'success')
            log_action(session['user_id'], f"Added question: {question_text}")
        except Exception as e:
            flash(f'Database error: {str(e)}', 'danger')
        finally:
            conn.close()
        return redirect(url_for('manage_questions'))
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
        conn.close()

@app.route('/view_logs')
def view_logs():
    if 'user_id' not in session or session['role'] not in ['admin', 'super_admin']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
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
        conn.close()

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.clear()
    flash('You have been logged out.', 'success')
    if user_id:
        log_action(user_id, "Logged out")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)