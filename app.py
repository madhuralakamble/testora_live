from flask import Flask, request, jsonify, send_from_directory, render_template, url_for, session, redirect, abort, make_response, send_file
import json
import os
from werkzeug.utils import secure_filename
import bcrypt
import uuid
import smtplib
from email.mime.text import MIMEText
from flask_cors import CORS
import re
import datetime
import time
from functools import wraps
import csv
import io
import traceback
import pandas as pd
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from flask_mail import Mail, Message
from datetime import datetime, timedelta, timezone

# ------------------------
# PostgreSQL setup
# ------------------------
import psycopg2
from psycopg2.extras import RealDictCursor

import os
print("Templates folder:", app.template_folder)
print("Files in templates:", os.listdir(app.template_folder))


def get_db_connection():
    """
    Returns a new PostgreSQL connection using environment variables.
    """
    conn = psycopg2.connect(
        host=os.getenv("PG_HOST"),
        port=os.getenv("PG_PORT"),
        database=os.getenv("PG_DB"),
        user=os.getenv("PG_USER"),
        password=os.getenv("PG_PASSWORD"),
        cursor_factory=RealDictCursor
    )
    return conn

# ------------------------
# Flask app setup
# ------------------------
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # project_root
FRONTEND_DIR = os.path.join(BASE_DIR, 'frontend')  # frontend folder path

app = Flask(
    __name__,
    static_folder=os.path.join(FRONTEND_DIR, 'static'),      # points to frontend/static
    template_folder=os.path.join(FRONTEND_DIR, 'templates'),  # points to frontend/templates
)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key'
CORS(app)

# ------------------------
# File uploads
# ------------------------
UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
# ------------------------
# Password validation
# ------------------------
def is_valid_password(password):
    """
    Validate password: at least 8 characters, one uppercase, one lowercase, one digit, one special character
    """
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return bool(re.match(pattern, password))

# ------------------------
# File uploads setup
# ------------------------
UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ------------------------
# Admin creation password
# ------------------------
ADMIN_CREATION_PASSWORD = os.getenv('ADMIN_CREATION_PASSWORD', 'admin123')
hashed_admin_creation_password = bcrypt.hashpw(
    ADMIN_CREATION_PASSWORD.encode('utf-8'),
    bcrypt.gensalt()
)


# ------------------------
# Basic routes
# ------------------------
@app.route('/')
def serve_homepage():
    css_ = url_for('static', filename='style.css')
    return render_template('index.html', css_path=css_)  # NOT send_from_directory

@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

@app.route('/login-page')
def serve_login():
    return render_template('login.html')

@app.route('/reset_password.html')
def reset_password_page():
    return render_template('reset_password.html')

# ------------------------
# Remove old MySQL config (replaced by PostgreSQL)
# ------------------------
# Old MySQL code removed:
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'madhura'  
# app.config['MYSQL_DB'] = 'testora_db'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# mysql = MySQL(app)

# ------------------------
# Email verification function
# ------------------------
def send_verification_email(to_email, token):
    verification_url = f"http://127.0.0.1:5000/verify-email/{token}"
    body = f"Please click the following link to verify your email:\n\n{verification_url}"

    msg = MIMEText(body)
    msg['Subject'] = "Verify Your Email for Testora"
    msg['From'] = os.getenv('EMAIL_USER')  # use environment variable
    msg['To'] = to_email

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587) 
        server.starttls()
        server.login(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASS'))  # secure login
        server.sendmail(msg['From'], [msg['To']], msg.as_string())
        server.quit()
        print(f"Verification email sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    role = data.get('role', 'student')  # default to student
    admin_creation_password = data.get('admin_creation_password')  # Optional for admin
    profile_completed = False
    verification_token = str(uuid.uuid4())
    added_by_admin = data.get('added_by_admin', False)
    
    if role == 'teacher' and added_by_admin:
        profile_completed = True

    # ------------------------
    # Validations
    # ------------------------
    if password != confirm_password:
        return jsonify({'error': "Passwords do not match."}), 400

    if not is_valid_password(password):
        return jsonify({'error': 'Password must be at least 8 characters and include uppercase, lowercase, digit, and special character.'}), 400
    
    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    if role == 'admin':
        if session.get('user_role') != 'superadmin':
            if not admin_creation_password:
                return jsonify({'error': 'Admin creation password is required for admin registration.'}), 403

            if not bcrypt.checkpw(admin_creation_password.encode('utf-8'), hashed_admin_creation_password):
                return jsonify({'error': 'Invalid admin creation password.'}), 403

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # ------------------------
    # Database insertion (PostgreSQL)
    # ------------------------
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        insert_query = """
            INSERT INTO users
            (username, full_name, email, password, role, is_verified, verification_token, profile_completed)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cur.execute(insert_query, (
            username, full_name, email, hashed_password, role, False, verification_token, profile_completed
        ))
        conn.commit()
        send_verification_email(email, verification_token)
    except psycopg2.errors.UniqueViolation as e:
        # Handle duplicate username/email
        conn.rollback()
        if 'username' in str(e):
            return jsonify({'error': 'Username already exists. Please choose another.'}), 400
        elif 'email' in str(e):
            return jsonify({'error': 'Email already registered.'}), 400
        else:
            return jsonify({'error': 'Registration failed due to unique constraint.'}), 400
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Registration Exception: {e}")
        return jsonify({'error': 'Registration failed due to server error.'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return jsonify({'message': 'User registered successfully. Please check your email to verify your account.'}), 201
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, username, password, role, is_verified, profile_completed, status
            FROM users
            WHERE email=%s
        """, (email,))
        user = cur.fetchone()
    except Exception as e:
        print(f"Login DB Exception: {e}")
        return jsonify({'error': 'Server error during login.'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    if user:
        user_id = user['id']
        username = user['username']
        hashed_password = user['password']
        role = user['role']
        is_verified = user['is_verified']
        status = user['status']
        profile_completed = user['profile_completed']

        if status == 'Deactive':
            return jsonify({'error': 'Account deactivated. Please contact administrator.'}), 403
        if not is_verified:
            return jsonify({'error': 'Email not verified. Please check your inbox.'}), 403
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            session['user_id'] = user_id
            session['user_role'] = role
            if not profile_completed:
                return jsonify({
                    'message': 'Login successful. Please complete your profile to continue.',
                    'redirect': url_for('complete_profile')
                })
            else:
                if role in ['superadmin', 'admin']:
                    return jsonify({'message': 'Login successful.', 'redirect': url_for('admin_dashboard')})
                elif role == 'teacher':
                    return jsonify({'message': 'Login successful.', 'redirect': url_for('teacher_dashboard')})
                else:
                    return jsonify({'message': 'Login successful.', 'redirect': url_for('student_dashboard')})
        else:
            return jsonify({'error': 'Incorrect password'}), 401
    else:
        return jsonify({'error': 'User not found'}), 404

# ------------------------
# Email verification route
# ------------------------
@app.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Check if token exists
        cur.execute("SELECT id FROM users WHERE verification_token=%s", (token,))
        user = cur.fetchone()

        if user:
            cur.execute(
                "UPDATE users SET is_verified=%s, verification_token=%s WHERE id=%s",
                (True, None, user['id'])
            )
            conn.commit()
            return redirect(url_for('serve_login'))  # redirect to login page
        else:
            return "Invalid or expired verification link.", 404

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Verify Email Exception: {e}")
        return "Server error during email verification.", 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# ------------------------
# Password change notification email
# ------------------------
def send_password_change_notification(to_email):
    subject = "Your Password Has Been Changed - Testora"
    body = (
        "Hello,\n\n"
        "This is to notify you that your password was successfully changed. "
        "If you did not perform this action, please contact support immediately.\n\n"
        "Thank you,\n"
        "Testora Team"
    )
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = os.getenv('EMAIL_USER')
    msg['To'] = to_email

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASS'))
        server.sendmail(msg['From'], [msg['To']], msg.as_string())
        server.quit()
        print(f"Password change notification sent to {to_email}")
    except Exception as e:
        print(f"Failed to send notification email: {e}")


# ------------------------
# Reset password route
# ------------------------
@app.route('/reset-password', methods=['POST'])
def reset_password_simple():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('password')
    confirm_password = data.get('confirm_password')

    # Validation
    if not email or not new_password or not confirm_password:
        return jsonify({'error': 'Email and passwords are required.'}), 400

    if new_password != confirm_password:
        return jsonify({'error': 'Passwords do not match.'}), 400

    if not is_valid_password(new_password):
        return jsonify({
            'error': 'Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.'
        }), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Check if user exists
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        user = cur.fetchone()

        if not user:
            return jsonify({'error': 'No user registered with this email.'}), 404

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cur.execute("UPDATE users SET password=%s WHERE id=%s", (hashed_password, user['id']))
        conn.commit()

        # Send notification email
        send_password_change_notification(email)

        return jsonify({'message': 'Password reset successful. You can now login.'})

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Reset Password Exception: {e}")
        return jsonify({'error': 'Server error during password reset.'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/complete-profile', methods=['GET', 'POST'])
def complete_profile():
    if 'user_id' not in session:
        return redirect(url_for('serve_login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if request.method == 'GET':
            # Fetch user's current profile
            cur.execute("SELECT profile_completed, email, role FROM users WHERE id=%s", (session['user_id'],))
            row = cur.fetchone()

            if row is None:
                return redirect(url_for('serve_login'))

            is_completed = row['profile_completed']
            email = row['email']
            user_role = row['role']

            if is_completed:
                if user_role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user_role == 'teacher':
                    return redirect(url_for('teacher_dashboard'))
                elif user_role == 'student':
                    return redirect(url_for('student_dashboard'))
                else:
                    return redirect(url_for('serve_login'))

            return render_template('complete_profile.html', email=email, role=user_role)

        elif request.method == 'POST':
            # Extract form data
            full_name = request.form.get('full_name')
            dob = request.form.get('dob')
            gender = request.form.get('gender')
            email = request.form.get('email')
            alt_email = request.form.get('alt_email')
            phone = request.form.get('phone')
            street = request.form.get('street')
            city = request.form.get('city')
            state = request.form.get('state')
            zip_code = request.form.get('zip')
            country = request.form.get('country')
            role = request.form.get('role')
            # Teacher fields
            department_teacher = request.form.get('department_teacher')
            courses_handling = request.form.get('courses_handling')
            designation = request.form.get('designation')
            experience = request.form.get('experience')
            experience = int(experience) if experience and experience.isdigit() else None
            qualifications = request.form.get('qualifications')
            # Student fields
            course = request.form.get('course')
            year_semester = request.form.get('year_semester')
            roll_no = request.form.get('roll_no')
            department_student = request.form.get('department_student')

            # Profile picture upload
            profile_picture = request.files.get('profile_picture')
            profile_picture_filename = None
            if profile_picture and allowed_file(profile_picture.filename):
                filename = secure_filename(profile_picture.filename)
                filename = f"user_{session['user_id']}_{filename}"
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                profile_picture.save(save_path)
                profile_picture_filename = filename
            elif profile_picture:
                return jsonify({'error': 'Invalid file type for profile picture.'}), 400

            # PostgreSQL update query
            if profile_picture_filename:
                cur.execute("""
                    UPDATE users 
                    SET full_name=%s, dob=%s, gender=%s, email=%s, alt_email=%s, phone=%s, street=%s, city=%s, 
                        state=%s, zip=%s, country=%s, role=%s, department_teacher=%s, courses_handling=%s, 
                        designation=%s, experience=%s, qualifications=%s, course=%s, year_semester=%s, roll_no=%s, 
                        department_student=%s, profile_picture=%s, profile_completed=%s
                    WHERE id=%s
                """, (
                    full_name, dob, gender, email, alt_email, phone, street, city, state, zip_code, country, 
                    role, department_teacher, courses_handling, designation, experience, qualifications, 
                    course, year_semester, roll_no, department_student, profile_picture_filename, True, session['user_id']
                ))
            else:
                cur.execute("""
                    UPDATE users 
                    SET full_name=%s, dob=%s, gender=%s, email=%s, alt_email=%s, phone=%s, street=%s, city=%s, 
                        state=%s, zip=%s, country=%s, role=%s, department_teacher=%s, courses_handling=%s, 
                        designation=%s, experience=%s, qualifications=%s, course=%s, year_semester=%s, roll_no=%s, 
                        department_student=%s, profile_completed=%s
                    WHERE id=%s
                """, (
                    full_name, dob, gender, email, alt_email, phone, street, city, state, zip_code, country, 
                    role, department_teacher, courses_handling, designation, experience, qualifications, 
                    course, year_semester, roll_no, department_student, True, session['user_id']
                ))

            conn.commit()

            # Fetch updated role
            cur.execute("SELECT role FROM users WHERE id=%s", (session['user_id'],))
            updated_role = cur.fetchone()['role']

            return jsonify({'message': 'Profile updated successfully', 'role': updated_role})

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Complete Profile Exception: {e}")
        return jsonify({'error': 'Server error during profile update.'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def no_cache(view):
    @wraps(view)
    def no_cache_impl(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return no_cache_impl

@app.route('/admin/dashboard')
@no_cache
def admin_dashboard():
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'superadmin']:
        return redirect(url_for('serve_login'))

    is_superadmin = (session.get('user_role') == 'superadmin')

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Counts
        cur.execute("SELECT COUNT(*) FROM users WHERE role='student'")
        students_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM users WHERE role='teacher'")
        teachers_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM exams")
        total_exams = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM questions")
        questions_count = cur.fetchone()[0]

        admins_count = 0
        if is_superadmin:
            cur.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
            admins_count = cur.fetchone()[0]

        # Fetch teachers
        cur.execute("""
            SELECT id, username, full_name, email, phone, dob, gender, 
                   department_teacher, courses_handling, designation, experience, qualifications, profile_picture, status
            FROM users WHERE role='teacher'
        """)
        teachers = cur.fetchall()

        # Fetch students
        cur.execute("""
            SELECT id, username, full_name, email, phone, dob, gender, 
                   course, year_semester, roll_no, department_student, profile_picture, status
            FROM users WHERE role='student'
        """)
        students = cur.fetchall()

        # Fetch admins
        cur.execute("""
            SELECT id, username, full_name, email, phone, dob, gender, profile_picture, status
            FROM users WHERE role='admin'
        """)
        admins = cur.fetchall()

        # Fetch current user info
        cur.execute("SELECT username, full_name, profile_picture FROM users WHERE id=%s", (session['user_id'],))
        user = cur.fetchone()
        if not user:
            return redirect(url_for('serve_login'))

        username = user['username']
        full_name = user['full_name']
        profile_picture = user['profile_picture']
        avatar_url = url_for('static', filename=f'uploads/{profile_picture}') if profile_picture else url_for('static', filename='admin icon.jpg')

        user_data = {
            'username': username,
            'full_name': full_name,
            'avatar_url': avatar_url,
            'role': session.get('user_role')
        }

    except Exception as e:
        print(f"Admin Dashboard Exception: {e}")
        return "Internal Server Error", 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return render_template('admin_dashboard.html', 
                           is_superadmin=is_superadmin,
                           teachers=teachers,
                           students=students,
                           admins=admins,
                           students_count=students_count,
                           teachers_count=teachers_count,
                           total_exams=total_exams,
                           admins_count=admins_count,
                           questions_count=questions_count,
                           user=user_data)
# Teacher section - PostgreSQL version
@app.route('/admin/teacher/<int:teacher_id>', methods=['GET'])
def get_teacher(teacher_id):
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'superadmin']:
        return jsonify({'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("""
            SELECT id, username, full_name, email, phone, dob, gender, department_teacher,
                   courses_handling, designation, experience, qualifications, profile_picture, status
            FROM users 
            WHERE id=%s AND role='teacher'
        """, (teacher_id,))
        teacher = cur.fetchone()

        if not teacher:
            return jsonify({'error': 'Teacher not found'}), 404

        # Convert dob to string
        if teacher['dob']:
            teacher['dob'] = teacher['dob'].strftime('%Y-%m-%d')

        # Profile picture URL
        teacher['profile_picture_url'] = (
            url_for('static', filename=f'uploads/{teacher["profile_picture"]}')
            if teacher.get('profile_picture') else url_for('static', filename='admin icon.jpg')
        )

        return jsonify(dict(teacher))  # convert DictCursor row to dict

    except Exception as e:
        print(f"Get Teacher Exception: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


@app.route('/admin/teacher/<int:teacher_id>', methods=['POST'])
def update_teacher(teacher_id):
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'superadmin']:
        return jsonify({'error': 'Unauthorized'}), 403

    # Extract form data
    full_name = request.form.get('full_name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    dob = request.form.get('dob')
    gender = request.form.get('gender')
    department_teacher = request.form.get('department_teacher')
    courses_handling = request.form.get('courses_handling')
    designation = request.form.get('designation')
    experience = request.form.get('experience')
    qualifications = request.form.get('qualifications')

    # Profile picture upload
    profile_picture_file = request.files.get('profile_picture')
    profile_picture_filename = None
    if profile_picture_file and allowed_file(profile_picture_file.filename):
        filename = secure_filename(profile_picture_file.filename)
        filename = f"user_{teacher_id}_{filename}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        profile_picture_file.save(save_path)
        profile_picture_filename = filename

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if profile_picture_filename:
            cur.execute("""
                UPDATE users 
                SET full_name=%s, email=%s, phone=%s, dob=%s, gender=%s, department_teacher=%s,
                    courses_handling=%s, designation=%s, experience=%s, qualifications=%s, profile_picture=%s
                WHERE id=%s
            """, (full_name, email, phone, dob, gender, department_teacher, courses_handling,
                  designation, experience, qualifications, profile_picture_filename, teacher_id))
        else:
            cur.execute("""
                UPDATE users 
                SET full_name=%s, email=%s, phone=%s, dob=%s, gender=%s, department_teacher=%s,
                    courses_handling=%s, designation=%s, experience=%s, qualifications=%s
                WHERE id=%s
            """, (full_name, email, phone, dob, gender, department_teacher, courses_handling,
                  designation, experience, qualifications, teacher_id))

        conn.commit()
        return jsonify({'message': 'Teacher data updated successfully.'})

    except Exception as e:
        print(f"Update Teacher Exception: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

# Delete teacher - PostgreSQL version
@app.route('/admin/teacher/<int:teacher_id>', methods=['DELETE'])
def delete_teacher(teacher_id):
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'superadmin']:
        return jsonify({'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("DELETE FROM users WHERE id=%s AND role='teacher'", (teacher_id,))
        conn.commit()

        if cur.rowcount == 0:
            return jsonify({'error': 'Teacher not found.'}), 404

        return jsonify({'message': 'Teacher deleted successfully.'})

    except Exception as e:
        print(f"Delete Teacher Exception: {e}")
        return jsonify({'error': 'Failed to delete teacher.'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Toggle teacher status - PostgreSQL version
@app.route('/admin/teacher/<int:teacher_id>/toggle-status', methods=['POST'])
def toggle_teacher_status(teacher_id):
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'superadmin']:
        return jsonify({'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("SELECT status FROM users WHERE id=%s AND role='teacher'", (teacher_id,))
        user = cur.fetchone()

        if not user:
            return jsonify({'error': 'Teacher not found'}), 404

        current_status = user['status']
        new_status = 'Deactive' if current_status == 'Active' else 'Active'

        cur.execute("UPDATE users SET status=%s WHERE id=%s", (new_status, teacher_id))
        conn.commit()

        return jsonify({'message': 'Status updated.', 'new_status': new_status})

    except Exception as e:
        print(f"Toggle Teacher Status Exception: {e}")
        return jsonify({'error': 'Failed to update status.'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Utility function for fetching one row as dict (if needed)
def fetchone_dict(cursor):
    row = cursor.fetchone()
    if row:
        return dict(row)
    return None


# Get student - PostgreSQL version
@app.route('/admin/student/<int:student_id>', methods=['GET'])
def get_student(student_id):
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'superadmin']:
        return jsonify({'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("""
            SELECT id, username, full_name, email, phone, dob, gender, 
                   course, year_semester, roll_no, department_student, profile_picture, status
            FROM users 
            WHERE id=%s AND role='student'
        """, (student_id,))

        student = cur.fetchone()
        if not student:
            return jsonify({'error': 'Student not found'}), 404

        if student['dob']:
            student['dob'] = student['dob'].strftime('%Y-%m-%d')

        student['profile_picture_url'] = (
            url_for('static', filename=f'uploads/{student["profile_picture"]}')
            if student.get('profile_picture') else url_for('static', filename='admin icon.jpg')
        )

        return jsonify(dict(student))

    except Exception as e:
        print(f"Get Student Exception: {e}")
        return jsonify({'error': 'Failed to fetch student'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Update student - PostgreSQL version
@app.route('/admin/student/<int:student_id>', methods=['POST'])
def update_student(student_id):
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'superadmin']:
        return jsonify({'error': 'Unauthorized'}), 403

    full_name = request.form.get('full_name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    dob = request.form.get('dob')
    gender = request.form.get('gender')
    course = request.form.get('course')
    year_semester = request.form.get('year_semester')
    roll_no = request.form.get('roll_no')
    department_student = request.form.get('department_student')

    profile_picture_file = request.files.get('profile_picture')
    profile_picture_filename = None

    if profile_picture_file and allowed_file(profile_picture_file.filename):
        filename = secure_filename(profile_picture_file.filename)
        filename = f"user_{student_id}_{filename}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        profile_picture_file.save(save_path)
        profile_picture_filename = filename

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if profile_picture_filename:
            cur.execute("""
                UPDATE users 
                SET full_name=%s, email=%s, phone=%s, dob=%s, gender=%s, 
                    course=%s, year_semester=%s, roll_no=%s, department_student=%s, profile_picture=%s 
                WHERE id=%s
            """, (full_name, email, phone, dob, gender, course, year_semester, roll_no, department_student, profile_picture_filename, student_id))
        else:
            cur.execute("""
                UPDATE users 
                SET full_name=%s, email=%s, phone=%s, dob=%s, gender=%s, 
                    course=%s, year_semester=%s, roll_no=%s, department_student=%s
                WHERE id=%s
            """, (full_name, email, phone, dob, gender, course, year_semester, roll_no, department_student, student_id))

        conn.commit()
        return jsonify({'message': 'Student Data updated successfully.'})

    except Exception as e:
        print(f"Update Student Exception: {e}")
        return jsonify({'error': 'Failed to update student'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

# Delete student - PostgreSQL
@app.route('/admin/student/<int:student_id>', methods=['DELETE'])
def delete_student(student_id):
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'superadmin']:
        return jsonify({'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id=%s AND role='student'", (student_id,))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Student not found.'}), 404
        return jsonify({'message': 'Student deleted successfully.'})
    except Exception as e:
        print(f"Delete Student Exception: {e}")
        return jsonify({'error': 'Failed to delete student.'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Toggle student active/deactive status - PostgreSQL
@app.route('/admin/student/<int:student_id>/toggle-status', methods=['POST'])
def toggle_student_status(student_id):
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'superadmin']:
        return jsonify({'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("SELECT status FROM users WHERE id=%s AND role='student'", (student_id,))
        user = cur.fetchone()
        if not user:
            return jsonify({'error': 'Student not found'}), 404

        current_status = user['status']
        new_status = 'Deactive' if current_status == 'Active' else 'Active'

        cur.execute("UPDATE users SET status=%s WHERE id=%s", (new_status, student_id))
        conn.commit()

        return jsonify({'message': 'Status updated.', 'new_status': new_status})
    except Exception as e:
        print(f"Toggle Student Status Exception: {e}")
        return jsonify({'error': 'Failed to update status.'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Superadmin: Get all admins - PostgreSQL
@app.route('/api/admins', methods=['GET'])
def get_admins():
    if 'user_id' not in session or session.get('user_role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT id, username, full_name, email FROM users WHERE role='admin'")
        admins = cur.fetchall()
        return jsonify([dict(admin) for admin in admins])
    except Exception as e:
        print(f"Get Admins Exception: {e}")
        return jsonify({'error': 'Failed to fetch admins'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

# Get admin details by admin_id - PostgreSQL
@app.route('/admin/admin/<int:admin_id>', methods=['GET'])
def get_admin(admin_id):
    if 'user_id' not in session or session.get('user_role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("""
            SELECT id, username, full_name, email, phone, dob, gender, profile_picture, status
            FROM users WHERE id=%s AND role='admin'
        """, (admin_id,))
        admin = cur.fetchone()

        if not admin:
            return jsonify({'error': 'Admin not found'}), 404

        if admin.get('dob'):
            admin['dob'] = admin['dob'].strftime('%Y-%m-%d')

        admin['profile_picture_url'] = (
            url_for('static', filename=f'uploads/{admin["profile_picture"]}')
            if admin.get('profile_picture') else url_for('static', filename='admin icon.jpg')
        )

        return jsonify(dict(admin))
    except Exception as e:
        print(f"Get Admin Exception: {e}")
        return jsonify({'error': 'Failed to fetch admin data'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Update admin profile - PostgreSQL
@app.route('/admin/admin/<int:admin_id>', methods=['POST'])
def update_admin(admin_id):
    if 'user_id' not in session or session.get('user_role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403

    full_name = request.form.get('full_name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    dob = request.form.get('dob')
    gender = request.form.get('gender')

    profile_picture_file = request.files.get('profile_picture')
    profile_picture_filename = None
    if profile_picture_file and allowed_file(profile_picture_file.filename):
        filename = secure_filename(profile_picture_file.filename)
        filename = f"user_{admin_id}_{filename}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        profile_picture_file.save(save_path)
        profile_picture_filename = filename

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if profile_picture_filename:
            cur.execute("""
                UPDATE users SET full_name=%s, email=%s, phone=%s, dob=%s, gender=%s, profile_picture=%s 
                WHERE id=%s
            """, (full_name, email, phone, dob, gender, profile_picture_filename, admin_id))
        else:
            cur.execute("""
                UPDATE users SET full_name=%s, email=%s, phone=%s, dob=%s, gender=%s 
                WHERE id=%s
            """, (full_name, email, phone, dob, gender, admin_id))
        conn.commit()
        return jsonify({'message': 'Admin Data updated successfully.'})
    except Exception as e:
        print(f"Update Admin Exception: {e}")
        return jsonify({'error': 'Failed to update admin'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Delete admin - PostgreSQL
@app.route('/admin/admin/<int:admin_id>', methods=['DELETE'])
def delete_admin(admin_id):
    if 'user_id' not in session or session.get('user_role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id=%s AND role='admin'", (admin_id,))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Admin not found.'}), 404
        return jsonify({'message': 'Admin deleted successfully.'})
    except Exception as e:
        print(f"Delete Admin Exception: {e}")
        return jsonify({'error': 'Failed to delete admin.'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

# Toggle admin status Active/Deactive - PostgreSQL
@app.route('/admin/admin/<int:admin_id>/toggle-status', methods=['POST'])
def toggle_admin_status(admin_id):
    if 'user_id' not in session or session.get('user_role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT status FROM users WHERE id=%s AND role='admin'", (admin_id,))
        user = cur.fetchone()
        if not user:
            return jsonify({'error': 'Admin not found'}), 404

        current_status = user['status']
        new_status = 'Deactive' if current_status == 'Active' else 'Active'

        cur.execute("UPDATE users SET status=%s WHERE id=%s", (new_status, admin_id))
        conn.commit()
        return jsonify({'message': 'Status updated.', 'new_status': new_status})
    except Exception as e:
        print(f"Toggle Admin Status Exception: {e}")
        return jsonify({'error': 'Failed to update status.'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Get logged-in admin profile - PostgreSQL
@app.route('/admin/get_profile', methods=['GET'])
def get_admin_profile():
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'superadmin']:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("""
            SELECT id, username, email, full_name, phone, dob, gender, alt_email, street, city,
                   state, zip, country, profile_picture
            FROM users WHERE id=%s AND role IN ('admin', 'superadmin')
        """, (user_id,))
        user = cur.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user['dob']:
            user['dob'] = user['dob'].strftime('%Y-%m-%d')

        user['profile_picture_url'] = (
            url_for('static', filename=f'uploads/{user["profile_picture"]}') 
            if user['profile_picture'] else url_for('static', filename='admin icon.jpg')
        )

        return jsonify(dict(user))
    except Exception as e:
        print(f"Get Admin Profile Exception: {e}")
        return jsonify({'error': 'Failed to fetch profile'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Update logged-in admin profile - PostgreSQL
@app.route('/admin/update_profile', methods=['POST'])
def update_admin_profile():
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'superadmin']:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    form = request.form

    # Collect form fields
    fields = ['full_name','phone','dob','gender','alt_email','street','city','state','zip','country']
    update_fields = []
    update_values = []

    for field in fields:
        value = form.get(field)
        if value is not None:
            update_fields.append(f"{field}=%s")
            update_values.append(value)

    # Handle profile picture
    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename = f"user_{user_id}_{filename}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(save_path)
            update_fields.append("profile_picture=%s")
            update_values.append(filename)
        elif file:
            return jsonify({'error': 'Invalid profile picture file type.'}), 400

    if not update_fields:
        return jsonify({'error': 'No data provided to update'}), 400

    update_values.append(user_id)
    sql = f"UPDATE users SET {', '.join(update_fields)} WHERE id=%s"

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(sql, tuple(update_values))
        conn.commit()
        return get_admin_profile()  # Return updated profile
    except Exception as e:
        print(f"Update Admin Profile Exception: {e}")
        return jsonify({'error': 'Database update failed', 'details': str(e)}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

import psycopg2.extras

# Student dashboard page
@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'student':
        return redirect(url_for('login'))

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT username, full_name, profile_picture FROM users WHERE id=%s", (session['user_id'],))
        user = cur.fetchone()

        if not user:
            return redirect(url_for('login'))

        profile_picture = user['profile_picture']
        student_url = url_for('static', filename=f'uploads/{profile_picture}') if profile_picture else url_for('static', filename='student icon.jpg')

        user_data = {
            'username': user['username'],
            'full_name': user['full_name'],
            'student_url': student_url,
            'role': 'student'
        }

        return render_template('student_dashboard.html', user=user_data)
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Student dashboard summary (assigned, pending, completed, upcoming exams)
@app.route('/api/student/dashboard_summary')
def student_dashboard_summary():
    if 'user_id' not in session or session.get('user_role') != 'student':
        return jsonify({'error': 'Unauthorized'}), 403

    user_id = session['user_id']
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Assigned exams
        cur.execute("SELECT COUNT(*) AS cnt FROM exam_assignments WHERE student_id=%s", (user_id,))
        assigned = cur.fetchone()['cnt'] or 0

        # Pending exams: exam date <= today and status Not Started / Ongoing
        cur.execute("""
            SELECT COUNT(*) AS cnt
            FROM exam_assignments ea
            JOIN exams e ON ea.exam_id = e.id
            WHERE ea.student_id=%s
              AND e.date <= CURRENT_DATE
              AND ea.status IN ('Not Started', 'Ongoing')
        """, (user_id,))
        pending = cur.fetchone()['cnt'] or 0

        # Completed exams
        cur.execute("""
            SELECT COUNT(*) AS cnt
            FROM exam_assignments
            WHERE student_id=%s AND status='Completed'
        """, (user_id,))
        completed = cur.fetchone()['cnt'] or 0

        # Upcoming exams: future exams, status Not Started
        cur.execute("""
            SELECT COUNT(*) AS cnt
            FROM exam_assignments ea
            JOIN exams e ON ea.exam_id = e.id
            WHERE ea.student_id=%s
              AND e.date > CURRENT_DATE
              AND ea.status='Not Started'
        """, (user_id,))
        upcoming = cur.fetchone()['cnt'] or 0

        return jsonify({
            'assignedExams': assigned,
            'pendingExams': pending,
            'completedExams': completed,
            'upcomingExams': upcoming
        })
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Get student profile
@app.route('/api/student/get_profile')
def get_student_profile():
    if 'user_id' not in session or session.get('user_role') != 'student':
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("""
            SELECT username, email, full_name, phone, dob, gender, alt_email,
                   street, city, state, zip, country, profile_picture,
                   course, year_semester, roll_no, department_student
            FROM users
            WHERE id = %s AND role = 'student'
        """, (user_id,))
        user = cur.fetchone()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user['dob']:
            user['dob'] = user['dob'].strftime('%Y-%m-%d')

        user['profile_picture_url'] = url_for(
            'static', filename=f'uploads/{user["profile_picture"]}'
        ) if user['profile_picture'] else url_for('static', filename='student icon.jpg')

        return jsonify(dict(user))
    finally:
        if cur: cur.close()
        if conn: conn.close()


import psycopg2.extras

# Update student profile
@app.route('/api/student/update_profile', methods=['POST'])
def update_student_profile():
    if 'user_id' not in session or session.get('user_role') != 'student':
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    form = request.form

    # Extract all possible fields
    fields = [
        'full_name', 'phone', 'dob', 'gender', 'alt_email', 'street', 'city', 
        'state', 'zip', 'country', 'course', 'year_semester', 'roll_no', 'department_student'
    ]
    update_fields = []
    update_values = []

    for field in fields:
        value = form.get(field)
        if value is not None:
            update_fields.append(f"{field}=%s")
            update_values.append(value)

    # Handle profile picture upload
    profile_picture_filename = None
    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename = f"user_{user_id}_{filename}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(save_path)
            profile_picture_filename = filename
            update_fields.append("profile_picture=%s")
            update_values.append(profile_picture_filename)
        elif file:
            return jsonify({'error': 'Invalid profile picture file type.'}), 400

    if not update_fields:
        return jsonify({'error': 'No fields provided to update'}), 400

    update_values.append(user_id)
    sql = f"UPDATE users SET {', '.join(update_fields)} WHERE id=%s"

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute(sql, tuple(update_values))
        conn.commit()
        return get_student_profile()  # return updated profile
    except Exception as e:
        return jsonify({'error': 'Database update failed', 'details': str(e)}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


# Get student exam assignments
@app.route('/api/student/exam_assignments')
def get_student_exam_assignments():
    if 'user_id' not in session or session.get('user_role') != 'student':
        return jsonify({'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("""
            SELECT ea.exam_id, e.title, e.subject, e.date, e.duration, ea.status, ea.link_token
            FROM exam_assignments ea
            JOIN exams e ON ea.exam_id = e.id
            WHERE ea.student_id = %s AND e.published = TRUE
            ORDER BY e.date DESC
        """, (session['user_id'],))
        assignments = cur.fetchall()
        return jsonify([dict(row) for row in assignments])
    finally:
        if cur: cur.close()
        if conn: conn.close()

import json
from io import BytesIO
from flask import session, jsonify, send_file
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from textwrap import wrap

# PostgreSQL cursor dict wrapper (if using psycopg2.extras.DictCursor)
import psycopg2
import psycopg2.extras

# ---------- STUDENT RESULTS ----------
@app.route('/api/student/results')
def student_results():
    if 'user_id' not in session or session.get('user_role') != 'student':
        return jsonify({'error': 'Unauthorized'}), 403

    user_id = session['user_id']
    cur = postgres_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)  # replace postgres_conn with your connection

    cur.execute("""
        SELECT 
            att.id AS attempt_id,
            e.id AS exam_id,
            e.title AS exam_name,
            att.score,
            att.end_time AS completed_at
        FROM exam_attempts att
        JOIN exam_assignments ea ON att.assignment_id = ea.id
        JOIN exams e ON ea.exam_id = e.id
        WHERE ea.student_id = %s
        ORDER BY att.end_time DESC
    """, (user_id,))
    results = cur.fetchall()
    cur.close()

    # Format datetime
    formatted_results = []
    for r in results:
        formatted_results.append({
            'attempt_id': r['attempt_id'],
            'exam_id': r['exam_id'],
            'exam_name': r['exam_name'],
            'score': r['score'],
            'completed_at': r['completed_at'].strftime('%Y-%m-%d %H:%M') if r['completed_at'] else None
        })

    return jsonify(formatted_results)

# ---------- EXAM REVIEW ----------
@app.route('/student/exam_review/<int:attempt_id>', methods=['GET'])
def exam_review(attempt_id):
    if 'user_id' not in session or session.get('user_role') != 'student':
        return jsonify({'error': 'Unauthorized'}), 403

    student_id = session['user_id']
    cur = postgres_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("""
        SELECT att.id AS attempt_id, att.answers, att.per_question_marks, att.score, att.grading_status, ea.exam_id
        FROM exam_attempts att
        JOIN exam_assignments ea ON att.assignment_id = ea.id
        WHERE att.id = %s AND ea.student_id = %s
    """, (attempt_id, student_id))
    attempt = cur.fetchone()
    if not attempt:
        cur.close()
        return jsonify({'error': 'No such attempt found'}), 404

    exam_id = attempt['exam_id']

    # Safe JSON parsing
    try:
        answers = json.loads(attempt['answers']) if attempt['answers'] else {}
        per_question_marks = json.loads(attempt['per_question_marks']) if attempt['per_question_marks'] else {}
    except Exception:
        answers = {}
        per_question_marks = {}

    cur.execute("""
        SELECT id AS question_id, question_text, question_type, correct_answer, marks
        FROM questions
        WHERE exam_id = %s
    """, (exam_id,))
    questions = cur.fetchall()
    cur.close()

    results = []
    for q in questions:
        qid_str = str(q['question_id'])
        marks_awarded = 0
        if attempt['grading_status'] != 'pending' or q['question_type'] != 'subjective':
            marks_awarded = per_question_marks.get(qid_str, 0)

        results.append({
            'question_id': q['question_id'],
            'question_text': q['question_text'],
            'question_type': q['question_type'],
            'correct_answer': q['correct_answer'],
            'max_marks': q['marks'] or 1,
            'student_answer': answers.get(qid_str, 'No Answer'),
            'marks_awarded': marks_awarded
        })

    return jsonify({
        'attempt_id': attempt['attempt_id'],
        'score': attempt['score'],
        'grading_status': attempt['grading_status'],
        'questions': results
    })

# ---------- EXAM ATTEMPT REPORT PDF ----------
def draw_wrapped_text(p, text, x, y, width=90, line_height=15):
    lines = wrap(text, width)
    for line in lines:
        p.drawString(x, y, line)
        y -= line_height
    return y

@app.route("/api/exam_attempt_report/<int:attempt_id>/report")
def exam_attempt_report(attempt_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    cur = postgres_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Student info
    cur.execute("SELECT email, full_name AS name FROM users WHERE id=%s", (user_id,))
    student = cur.fetchone()

    # Attempt info
    cur.execute("""
        SELECT ea.exam_id, att.score, att.grading_status, att.answers, att.per_question_marks
        FROM exam_attempts att
        JOIN exam_assignments ea ON att.assignment_id = ea.id
        WHERE att.id=%s AND ea.student_id=%s
    """, (attempt_id, user_id))
    attempt = cur.fetchone()
    if not attempt:
        cur.close()
        return jsonify({"error": "No such attempt"}), 404

    exam_id = attempt['exam_id']

    # Exam info
    cur.execute("SELECT title FROM exams WHERE id=%s", (exam_id,))
    exam = cur.fetchone()

    # Questions
    cur.execute("""
        SELECT id AS question_id, question_text, question_type, correct_answer
        FROM questions
        WHERE exam_id = %s
    """, (exam_id,))
    questions = cur.fetchall()
    cur.close()

    # Safe JSON parse
    try:
        answers = json.loads(attempt['answers']) if attempt['answers'] else {}
        per_question_marks = json.loads(attempt['per_question_marks']) if attempt['per_question_marks'] else {}
    except Exception:
        answers = {}
        per_question_marks = {}

    # Prepare question details
    question_details = []
    for q in questions:
        qid_str = str(q['question_id'])
        question_details.append({
            'question_text': q['question_text'],
            'your_answer': answers.get(qid_str, 'No Answer'),
            'correct_answer': q['correct_answer'],
            'marks_awarded': per_question_marks.get(qid_str, 0)
        })

    # Generate PDF
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, 750, "Exam Report Card")
    p.setFont("Helvetica", 12)
    p.drawString(100, 720, f"Student: {student['name']}")
    p.drawString(100, 700, f"Exam: {exam['title']}")
    p.drawString(100, 680, f"Score: {attempt['score']}")
    p.drawString(100, 660, f"Grading Status: {attempt['grading_status']}")

    y = 630
    for idx, q in enumerate(question_details, 1):
        if y < 80:
            p.showPage()
            y = 750
        y = draw_wrapped_text(p, f"Q{idx}: {q['question_text']}", 100, y)
        y = draw_wrapped_text(p, f"Your Answer: {q['your_answer']}", 120, y)
        y = draw_wrapped_text(p, f"Correct Answer: {q['correct_answer']}", 120, y)
        p.drawString(120, y, f"Marks Awarded: {q['marks_awarded']}")
        y -= 25

    p.showPage()
    p.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name='exam_report.pdf', mimetype='application/pdf')


import json
from io import BytesIO
from flask import session, jsonify, render_template, url_for, redirect
from flask_mail import Message
from reportlab.pdfgen import canvas
from datetime import datetime, timezone, timedelta

import psycopg2
import psycopg2.extras

# ---------- EXPORT STUDENT RESULTS TO PDF AND EMAIL ----------
@app.route('/api/student/export', methods=['POST'])
def export_results():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    cur = postgres_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Get student info
    cur.execute("SELECT email, full_name AS name FROM users WHERE id=%s", (user_id,))
    student = cur.fetchone()
    if not student:
        cur.close()
        return jsonify({"error": "Student not found"}), 404

    # Fetch results with exam names
    cur.execute("""
        SELECT ea.id AS assignment_id, e.title AS exam_name, ea.score, ea.end_time AS completed_at
        FROM exam_attempts ea
        JOIN exam_assignments ea2 ON ea.assignment_id = ea2.id
        JOIN exams e ON ea2.exam_id = e.id
        WHERE ea.student_id = %s AND ea.status = 'completed'
        ORDER BY ea.end_time DESC
    """, (user_id,))
    exams = cur.fetchall()
    cur.close()

    # Generate PDF in memory
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, 800, "Student Exam Results Report")
    p.setFont("Helvetica", 12)
    p.drawString(100, 780, f"Student: {student['name']}")
    y = 750

    for exam in exams:
        p.drawString(100, y, f"Exam: {exam['exam_name']}")
        p.drawString(100, y - 15, f"Score: {exam['score']}")
        completed_at_str = exam['completed_at'].strftime('%Y-%m-%d %H:%M') if exam['completed_at'] else 'N/A'
        p.drawString(100, y - 30, f"Completed At: {completed_at_str}")
        y -= 60
        if y < 100:
            p.showPage()
            y = 800

    p.save()
    buffer.seek(0)

    # Send email with PDF attachment
    msg = Message("Your Exam Results Report",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[student['email']])
    msg.body = "Please find attached your exam results report."
    msg.attach("exam_results.pdf", "application/pdf", buffer.read())

    mail.send(msg)

    return jsonify({"message": "Report emailed successfully!"})


# ---------- START EXAM ----------
@app.route('/exam/start/<int:exam_id>/<token>', methods=['GET'])
def start_exam(exam_id, token):
    if 'user_id' not in session or session.get('user_role') != 'student':
        return redirect(url_for('login'))

    cur = postgres_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Fetch the assignment
    cur.execute("""
        SELECT ea.*, u.id AS student_id, u.full_name, u.username, u.profile_picture,
               e.title, e.subject, e.date, e.duration, e.description
        FROM exam_assignments ea
        JOIN users u ON ea.student_id = u.id
        JOIN exams e ON ea.exam_id = e.id
        WHERE ea.exam_id=%s AND ea.link_token=%s AND ea.student_id=%s 
          AND ea.status IN ('Not Started', 'Ongoing')
        LIMIT 1
    """, (exam_id, token, session['user_id']))
    assignment = cur.fetchone()

    if not assignment:
        cur.close()
        return "Invalid or expired exam link, or not authorized.", 404

    # Check if an ongoing attempt exists
    cur.execute("SELECT * FROM exam_attempts WHERE assignment_id=%s AND status='in_progress'", (assignment['id'],))
    ongoing_attempt = cur.fetchone()
    if ongoing_attempt:
        cur.close()
        return "You already have an ongoing exam attempt. Please complete it.", 403

    # Check expiry
    created_at = assignment['assign_time']
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    expiry_duration = timedelta(hours=24)
    if now > created_at + expiry_duration:
        cur.close()
        return "This exam link has expired. Contact support.", 403

    # Insert new attempt
    cur.execute("""
        INSERT INTO exam_attempts (assignment_id, student_id, start_time, status)
        VALUES (%s, %s, NOW(), 'in_progress')
    """, (assignment['id'], assignment['student_id']))
    postgres_conn.commit()
    cur.close()

    # Prepare student info
    profile_picture = assignment['profile_picture']
    student_url = url_for('static', filename=f'uploads/{profile_picture}') if profile_picture else url_for('static', filename='student icon.jpg')

    exam = {
        "id": exam_id,
        "title": assignment['title'],
        "subject": assignment['subject'],
        "date": assignment['date'].strftime("%Y-%m-%d"),
        "duration": assignment['duration'],
        "description": assignment['description']
    }
    student = {
        "id": assignment['student_id'],
        "name": assignment['full_name'],
        "username": assignment['username'],
        "student_url": student_url,
        "role": 'student'
    }

    return render_template('exam_start.html', exam=exam, student=student, token=token)

import json
from flask import session, jsonify, render_template, url_for, redirect, request
import psycopg2
import psycopg2.extras

# --------------------- STUDENT EXAM QUESTIONS ---------------------
@app.route('/api/exams/<int:exam_id>/questions', methods=['GET'])
def get_exam_questions(exam_id):
    cur = postgres_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM questions WHERE exam_id=%s", (exam_id,))
    questions = cur.fetchall()
    cur.close()

    q_list = []
    for q in questions:
        options = []
        if q['question_type'] == 'objective' and q['options']:
            try:
                options = json.loads(q['options'])
            except (json.JSONDecodeError, TypeError):
                options = q['options'].split(';') if q['options'] else []

        q_list.append({
            'id': q['id'],
            'question_text': q['question_text'],
            'question_type': q['question_type'],
            'options': options,
            'correct_answer': q.get('correct_answer', '')
        })

    return jsonify({'questions': q_list})


# --------------------- STUDENT EXAM RESULT ---------------------
@app.route("/exam/<int:exam_id>/result")
def exam_result(exam_id):
    token = request.args.get("token")
    if "user_id" not in session or session.get("user_role") != "student":
        return "Unauthorized", 403

    student_id = session["user_id"]
    cur = postgres_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("""
        SELECT att.id AS attempt_id
        FROM exam_assignments ea
        JOIN exam_attempts att ON att.assignment_id=ea.id
        WHERE ea.exam_id=%s AND ea.link_token=%s AND ea.student_id=%s
        ORDER BY att.start_time DESC
        LIMIT 1
    """, (exam_id, token, student_id))
    row = cur.fetchone()

    cur.execute("SELECT title FROM exams WHERE id=%s", (exam_id,))
    exam_row = cur.fetchone()
    exam_title = exam_row['title'] if exam_row else 'Unknown'
    cur.close()

    attempt_id = row['attempt_id'] if row else None

    if not attempt_id:
        return "Result not found", 404

    return render_template("exam_result.html", attempt_id=attempt_id, exam_title=exam_title)


# --------------------- TEACHER DASHBOARD ---------------------
@app.route('/teacher/dashboard')
def teacher_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return redirect(url_for('login'))

    cur = postgres_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT username, full_name, profile_picture FROM users WHERE id=%s", (session['user_id'],))
    user = cur.fetchone()
    cur.close()

    if not user:
        return redirect(url_for('login'))

    profile_picture = user['profile_picture']
    teacher_url = url_for('static', filename=f'uploads/{profile_picture}') if profile_picture else url_for('static', filename='teacher icon.jpg')
    user_data = {
        'username': user['username'],
        'full_name': user['full_name'],
        'teacher_url': teacher_url,
        'role': 'teacher'
    }

    return render_template('teacher_dashboard.html', user=user_data)


# --------------------- TEACHER PROFILE ---------------------
@app.route('/api/teacher/get_profile')
def get_teacher_profile():
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    cur = postgres_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("""
        SELECT username, email, full_name, phone, dob, gender, alt_email, street, city, state, zip, country, profile_picture,
               department_teacher, courses_handling, designation, experience, qualifications
        FROM users
        WHERE id=%s AND role='teacher'
    """, (user_id,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user['dob']:
        user['dob'] = user['dob'].strftime('%Y-%m-%d')

    user['profile_picture_url'] = url_for('static', filename=f'uploads/{user["profile_picture"]}') if user['profile_picture'] else url_for('static', filename='teacher icon.jpg')

    return jsonify(user)

import os
import json
from flask import session, request, jsonify, url_for
from werkzeug.utils import secure_filename
from datetime import datetime, time, timedelta

# ---------------- TEACHER PROFILE UPDATE ----------------
@app.route('/api/teacher/update_profile', methods=['POST'])
def update_teacher_profile():
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    form = request.form

    # Collect form fields
    full_name = form.get('full_name')
    phone = form.get('phone')
    dob = form.get('dob')
    gender = form.get('gender')
    alt_email = form.get('alt_email')
    street = form.get('street')
    city = form.get('city')
    state = form.get('state')
    zip_code = form.get('zip')
    country = form.get('country')
    department_teacher = form.get('department_teacher')
    courses_handling = form.get('courses_handling')
    designation = form.get('designation')
    experience = form.get('experience')
    qualifications = form.get('qualifications')

    # Handle profile picture
    profile_picture_filename = None
    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename = f"user_{user_id}_{filename}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(save_path)
            profile_picture_filename = filename
        elif file:
            return jsonify({'error': 'Invalid profile picture file type.'}), 400

    try:
        cursor = postgres_conn.cursor()  # PostgreSQL cursor
        update_fields = []
        update_values = []

        # Build dynamic update query
        field_map = {
            'full_name': full_name, 'phone': phone, 'dob': dob, 'gender': gender, 'alt_email': alt_email,
            'street': street, 'city': city, 'state': state, 'zip': zip_code, 'country': country,
            'department_teacher': department_teacher, 'courses_handling': courses_handling,
            'designation': designation, 'experience': experience, 'qualifications': qualifications,
            'profile_picture': profile_picture_filename
        }

        for key, value in field_map.items():
            if value is not None:
                update_fields.append(f"{key}=%s")
                update_values.append(value)

        if not update_fields:
            return jsonify({'error': 'No data provided to update'}), 400

        update_values.append(user_id)
        sql = f"UPDATE users SET {', '.join(update_fields)} WHERE id=%s"
        cursor.execute(sql, tuple(update_values))
        postgres_conn.commit()
        cursor.close()

        return get_teacher_profile()  # Return updated profile

    except Exception as e:
        return jsonify({'error': 'Database update failed', 'details': str(e)}), 500


# ---------------- HELPER FUNCTIONS ----------------
def minutes_to_time_str(minutes):
    """Convert minutes to HH:MM string"""
    h = minutes // 60
    m = minutes % 60
    return f"{h:02d}:{m:02d}"


def serialize_exam(exam):
    """Recursively serialize exam dict, handling datetime, time, timedelta"""
    serialized = {}
    for key, value in exam.items():
        if isinstance(value, datetime):
            if key == 'date':
                serialized[key] = value.strftime("%Y-%m-%d")
            else:
                serialized[key] = value.strftime("%H:%M:%S")
        elif isinstance(value, time):
            serialized[key] = value.strftime("%H:%M:%S")
        elif isinstance(value, timedelta):
            serialized[key] = int(value.total_seconds() // 60)  # total minutes
        elif isinstance(value, dict):
            serialized[key] = serialize_exam(value)
        elif isinstance(value, list):
            serialized[key] = [serialize_exam(v) if isinstance(v, dict) else v for v in value]
        else:
            serialized[key] = value
    return serialized

from flask import session, request, jsonify
from datetime import datetime

# ---------------- TEACHER DASHBOARD STATS ----------------
@app.route('/api/teacher/dashboard_stats', methods=['GET'])
def teacher_dashboard_stats():
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    teacher_id = session['user_id']
    cur = postgres_conn.cursor()

    # My Exams
    cur.execute("SELECT COUNT(*) FROM exams WHERE teacher_id = %s", (teacher_id,))
    exams_count = cur.fetchone()[0]

    # Students Monitored
    cur.execute("""
        SELECT COUNT(DISTINCT ea.student_id)
        FROM exam_assignments ea
        JOIN exams ex ON ea.exam_id = ex.id
        WHERE ex.teacher_id = %s
    """, (teacher_id,))
    students_count = cur.fetchone()[0]

    # Pending Grading
    cur.execute("""
        SELECT COUNT(*)
        FROM exam_attempts att
        JOIN exam_assignments ea ON att.assignment_id = ea.id
        JOIN exams ex ON ea.exam_id = ex.id
        WHERE ex.teacher_id = %s AND att.grading_status = 'pending'
    """, (teacher_id,))
    pending_count = cur.fetchone()[0]

    # Exams Completed
    cur.execute("""
        SELECT COUNT(*)
        FROM exam_attempts att
        JOIN exam_assignments ea ON att.assignment_id = ea.id
        JOIN exams ex ON ea.exam_id = ex.id
        WHERE ex.teacher_id = %s AND att.grading_status = 'completed'
    """, (teacher_id,))
    completed_count = cur.fetchone()[0]

    cur.close()
    return jsonify({
        "my_exams": exams_count,
        "students_monitored": students_count,
        "pending_grading": pending_count,
        "exams_completed": completed_count
    })


# ---------------- MANAGE EXAMS ----------------
@app.route('/api/exams', methods=['GET', 'POST'])
def manage_exams():
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    if request.method == 'GET':
        cur = postgres_conn.cursor()
        cur.execute("""
            SELECT id, title, subject, date, duration, published, status
            FROM exams
            WHERE teacher_id = %s
        """, (session['user_id'],))
        exams = cur.fetchall()
        cur.close()

        exams_serialized = [serialize_exam(dict(zip([desc[0] for desc in cur.description], row))) for row in exams] if exams else []
        return jsonify(exams_serialized)

    if request.method == 'POST':
        data = request.json
        title = data['title']
        subject = data['subject']
        date = data['date']  # Expected "YYYY-MM-DD"
        duration = int(data['duration'])
        description = data.get('description', '')
        status = "Upcoming"

        cur = postgres_conn.cursor()
        cur.execute("""
            INSERT INTO exams (teacher_id, title, subject, date, duration, description, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (session['user_id'], title, subject, date, duration, description, status))
        postgres_conn.commit()
        cur.close()

        return jsonify({"message": "Exam created successfully."}), 201


# ---------------- UPDATE EXAM ----------------
@app.route('/api/exams/<int:exam_id>', methods=['PUT'])
def update_exam(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    title = data.get('title')
    subject = data.get('subject')
    date = data.get('date')
    duration = data.get('duration')
    description = data.get('description')

    try:
        cur = postgres_conn.cursor()
        cur.execute("""
            UPDATE exams
            SET title=%s, subject=%s, date=%s, duration=%s, description=%s
            WHERE id=%s AND teacher_id=%s
        """, (title, subject, date, duration, description, exam_id, session['user_id']))
        postgres_conn.commit()
        cur.close()
        return jsonify({"message": "Exam updated successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- DELETE EXAM ----------------
@app.route('/api/exams/<int:exam_id>', methods=['DELETE'])
def delete_exam(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    try:
        cur = postgres_conn.cursor()

        # Delete all exam attempts linked to this exam
        cur.execute("""
            DELETE FROM exam_attempts
            WHERE assignment_id IN (
                SELECT id FROM exam_assignments WHERE exam_id=%s
            )
        """, (exam_id,))

        # Delete exam assignments
        cur.execute("DELETE FROM exam_assignments WHERE exam_id=%s", (exam_id,))

        # Delete exam links
        cur.execute("DELETE FROM exam_links WHERE exam_id=%s", (exam_id,))

        # Delete questions
        cur.execute("DELETE FROM questions WHERE exam_id=%s", (exam_id,))

        # Delete the exam
        cur.execute("DELETE FROM exams WHERE id=%s AND teacher_id=%s", (exam_id, session['user_id']))

        postgres_conn.commit()
        cur.close()
        return jsonify({"message": "Exam deleted successfully."})
    except Exception as e:
        return jsonify({"error": f"Delete failed: {str(e)}"}), 500

from flask import session, request, jsonify
import json, csv, io
from datetime import datetime

# ---------------- GET SINGLE QUESTION ----------------
@app.route('/api/questions/<int:question_id>', methods=['GET'])
def get_question(question_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    cur = postgres_conn.cursor()
    cur.execute("SELECT * FROM questions WHERE id=%s", (question_id,))
    row = cur.fetchone()
    cur.close()

    if not row:
        return jsonify({"error": "Question not found"}), 404

    columns = [desc[0] for desc in cur.description]
    question = dict(zip(columns, row))
    return jsonify(question)


# ---------------- ADD QUESTION ----------------
@app.route('/api/exams/<int:exam_id>/questions', methods=['POST'])
def add_question(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    question_text = data.get('question_text')
    question_type = data.get('question_type')
    options = json.dumps(data.get('options')) if data.get('options') else None
    correct_answer = data.get('correct_answer')
    difficulty = data.get('difficulty')
    marks = data.get('marks', 1)

    cur = postgres_conn.cursor()
    cur.execute("""
        INSERT INTO questions (exam_id, question_text, question_type, options, correct_answer, difficulty, marks)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (exam_id, question_text, question_type, options, correct_answer, difficulty, marks))
    postgres_conn.commit()
    cur.close()
    return jsonify({"message": "Question added successfully."}), 201


# ---------------- GET EXAM ----------------
@app.route('/api/exams/<int:exam_id>', methods=['GET'])
def get_exam(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    cur = postgres_conn.cursor()
    cur.execute("""
        SELECT id, title, subject, date, duration, description
        FROM exams
        WHERE id=%s AND teacher_id=%s
    """, (exam_id, session['user_id']))
    row = cur.fetchone()
    cur.close()

    if not row:
        return jsonify({"error": "Exam not found"}), 404

    columns = [desc[0] for desc in cur.description]
    exam = dict(zip(columns, row))
    return jsonify(exam)


# ---------------- UPDATE QUESTION ----------------
@app.route('/api/questions/<int:question_id>', methods=['PUT'])
def update_question(question_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    question_text = data.get('question_text')
    question_type = data.get('question_type')
    options = json.dumps(data.get('options')) if data.get('options') else None
    correct_answer = data.get('correct_answer')
    difficulty = data.get('difficulty')
    marks = data.get('marks', 1)

    cur = postgres_conn.cursor()
    cur.execute("""
        UPDATE questions
        SET question_text=%s, question_type=%s, options=%s, correct_answer=%s, difficulty=%s, marks=%s
        WHERE id=%s
    """, (question_text, question_type, options, correct_answer, difficulty, marks, question_id))
    postgres_conn.commit()
    cur.close()
    return jsonify({"message": "Question updated successfully."})


# ---------------- DELETE QUESTION ----------------
@app.route('/api/questions/<int:question_id>', methods=['DELETE'])
def delete_question(question_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    cur = postgres_conn.cursor()
    cur.execute("DELETE FROM questions WHERE id=%s", (question_id,))
    postgres_conn.commit()
    cur.close()
    return jsonify({"message": "Question deleted successfully."})


# ---------------- LIVE MONITOR ----------------
@app.route('/api/exams/<int:exam_id>/live_monitor', methods=['GET'])
def live_monitor(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    cur = postgres_conn.cursor()
    cur.execute("""
        SELECT 
            u.full_name AS name,
            ea.status AS exam_status,
            ea.assign_time,
            att.status AS attempt_status,
            att.start_time,
            att.end_time,
            att.score,
            ea.cheating_submission
        FROM exam_assignments ea
        JOIN users u ON ea.student_id = u.id
        LEFT JOIN exam_attempts att ON att.assignment_id = ea.id
        WHERE ea.exam_id = %s
        ORDER BY att.start_time DESC NULLS LAST
    """, (exam_id,))
    rows = cur.fetchall()
    columns = [desc[0] for desc in cur.description]
    cur.close()

    monitor_data = []
    for r in rows:
        record = dict(zip(columns, r))
        monitor_data.append({
            "name": record['name'],
            "status": record['attempt_status'] if record['attempt_status'] else record['exam_status'],
            "start_time": record['start_time'].strftime("%H:%M:%S") if record['start_time'] else "--",
            "end_time": record['end_time'].strftime("%H:%M:%S") if record['end_time'] else "--",
            "score": record['score'] if record['score'] is not None else "--",
            "cheating_submission": "Yes" if record.get('cheating_submission') else "No"
        })
    return jsonify(monitor_data)


# ---------------- CYCLE EXAM STATUS ----------------
@app.route('/api/exams/<int:exam_id>/cycle_status', methods=['POST'])
def cycle_status(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    statuses = ['Upcoming', 'Ongoing', 'Completed', 'Cancelled']
    cur = postgres_conn.cursor()
    cur.execute("SELECT status FROM exams WHERE id=%s AND teacher_id=%s", (exam_id, session['user_id']))
    row = cur.fetchone()

    if not row:
        cur.close()
        return jsonify({"error": "Exam not found"}), 404

    current_status = row[0]
    try:
        current_index = statuses.index(current_status)
    except ValueError:
        current_index = 0

    new_index = (current_index + 1) % len(statuses)
    new_status = statuses[new_index]

    cur.execute("UPDATE exams SET status=%s WHERE id=%s AND teacher_id=%s", (new_status, exam_id, session['user_id']))
    postgres_conn.commit()
    cur.close()
    return jsonify({"message": f"Status changed to {new_status}.", "status": new_status})


# ---------------- IMPORT QUESTIONS FROM CSV ----------------
@app.route('/api/exams/<int:exam_id>/import_csv', methods=['POST'])
def import_questions_csv(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if not file.filename.endswith('.csv'):
        return jsonify({"error": "Invalid file type"}), 400

    stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
    reader = csv.DictReader(stream)
    added = 0
    cur = postgres_conn.cursor()

    for row in reader:
        question_text = row.get('question_text') or row.get('text')
        question_type = row.get('question_type') or 'objective'
        options = row.get('options')
        correct_answer = row.get('correct_answer')
        marks = int(row.get('marks') or 1)
        difficulty = row.get('difficulty') or 'Medium'

        if question_type == 'objective' and options:
            options = options.split(';')
        else:
            options = []

        cur.execute("""
            INSERT INTO questions (exam_id, question_text, question_type, options, correct_answer, difficulty, marks)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            exam_id, question_text, question_type,
            json.dumps(options) if options else None,
            correct_answer, difficulty, marks
        ))
        added += 1

    postgres_conn.commit()
    cur.close()
    return jsonify({'message': f'Imported {added} questions successfully'})

@app.route('/api/exams/<int:exam_id>/toggle_publish', methods=['POST'])
def toggle_publish(exam_id):
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("UPDATE exams SET published = NOT published WHERE id = %s", (exam_id,))
        mysql.connection.commit()

        cur.execute("SELECT published FROM exams WHERE id = %s", (exam_id,))
        row = cur.fetchone()
        cur.close()

        if not row:
            return jsonify({'error': 'Exam not found'}), 404

        return jsonify({'published': bool(row['published']), 'message': 'Publish status updated.'})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error_type': type(e).__name__, 'error_message': str(e)}), 500

@app.route('/api/exams/<int:exam_id>/update_status', methods=['POST'])
def update_status(exam_id):
    new_status = request.json.get('status')
    valid_exam_statuses = ['Upcoming', 'Ongoing', 'Completed', 'Cancelled']
    
    if new_status not in valid_exam_statuses:
        return jsonify({'error': 'Invalid status'}), 400

    status_map = {
        'Upcoming': 'Not Started',
        'Ongoing': 'Ongoing',
        'Completed': 'Submitted',
        'Cancelled': 'Not Started'  
    }
    assignment_status = status_map.get(new_status, 'Not Started')

    try:
        cur = mysql.connection.cursor()
        # Update exam status
        cur.execute("UPDATE exams SET status = %s WHERE id = %s", (new_status, exam_id))
        # Update related assignments
        cur.execute("UPDATE exam_assignments SET status = %s WHERE exam_id = %s", (assignment_status, exam_id))
        mysql.connection.commit()
        cur.close()
        return jsonify({'status': new_status, 'message': 'Status updated successfully'})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@app.route('/api/exams/<int:exam_id>/send-links', methods=['POST'])
def send_exam_links_all_students(exam_id):
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("""
            SELECT ea.id AS assignment_id, ea.student_id, ea.link_token, u.full_name, u.email,
                   e.title, e.subject, e.date, e.duration, e.description
            FROM exam_assignments ea
            JOIN users u ON ea.student_id = u.id
            JOIN exams e ON ea.exam_id = e.id
            WHERE ea.exam_id = %s
        """, (exam_id,))
        assignments = cur.fetchall()
        if not assignments:
            cur.close()
            return jsonify({'message': 'No students assigned or all submitted.'}), 404

        for assign in assignments:
            token = assign['link_token'] or str(uuid.uuid4())
            if not assign['link_token']:
                cur.execute("""
                    UPDATE exam_assignments
                    SET link_token=%s, assign_time=NOW(), status='Ongoing'
                    WHERE id=%s
                """, (token, assign['assignment_id']))
            else:
                cur.execute("""
                    UPDATE exam_assignments
                    SET status='Ongoing'
                    WHERE id=%s
                """, (assign['assignment_id'],))
            mysql.connection.commit()

            # Send email
            exam_link_url = f"http://127.0.0.1:5000/exam/start/{exam_id}/{token}"
            body = f"""Dear {assign['full_name']},

You are invited to take the exam '{assign['title']}' ({assign['subject']}).
Exam Date: {assign['date']}
Duration: {assign['duration']} minutes

Instructions:
{assign['description']}

Access the exam here: {exam_link_url}

Best regards,
Testora Team
"""
            msg = MIMEText(body)
            msg['Subject'] = f"Your Exam Link for '{assign['title']}' - Testora"
            msg['From'] = "testoraofficial@gmail.com"
            msg['To'] = assign['email']

            try:
                server = smtplib.SMTP('smtp.gmail.com', 587)
                server.starttls()
                server.login("testoraofficial@gmail.com", "hmcq wpoo pexe uxrs")  # App password
                server.sendmail(msg['From'], [msg['To']], msg.as_string())
                server.quit()
            except Exception as e:
                print(f"Failed to send email to {assign['email']}: {e}")

        cur.close()
        return jsonify({'message': 'Exam links sent successfully.'}), 200

    except Exception as e:
        print(f"Error sending exam links: {e}")
        return jsonify({'message': 'Failed to send exam links.', 'error': str(e)}), 500

def assign_exam_to_students(exam_id, student_ids):
    cur = mysql.connection.cursor()

    for student_id in student_ids:
        token = str(uuid.uuid4())
        cur.execute("SELECT id FROM exam_assignments WHERE exam_id=%s AND student_id=%s", (exam_id, student_id))
        existing = cur.fetchone()

        if existing:
            cur.execute("""
                UPDATE exam_assignments
                SET link_token=%s, status='Not Started', assign_time=NOW()
                WHERE id=%s
            """, (token, existing[0]))
        else:
            cur.execute("""
                INSERT INTO exam_assignments (exam_id, student_id, link_token, status, assign_time)
                VALUES (%s, %s, %s, 'Not Started', NOW())
            """, (exam_id, student_id, token))

    mysql.connection.commit()
    cur.close()

@app.route('/api/students', methods=['GET'])
def get_students():
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT id, full_name, email, username, status FROM users WHERE role='student'")
        students = cur.fetchall()
        cur.close()
        return jsonify(students)
    except Exception as e:
        print(f"Error fetching students: {e}")
        return jsonify({'message': 'Failed to fetch students.', 'error': str(e)}), 500

@app.route('/api/exams/<int:exam_id>/assign-students', methods=['POST'])
def assign_students_to_exam(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    if not data or 'studentIds' not in data or not isinstance(data['studentIds'], list):
        return jsonify({"error": "Malformed input. 'studentIds' array is required."}), 400
    student_ids = data['studentIds']
    if not student_ids:
        return jsonify({'message': 'No students selected for assignment.'}), 400

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    import uuid

    for student_id in student_ids:
        token = str(uuid.uuid4())
        cur.execute("SELECT id FROM exam_assignments WHERE exam_id=%s AND student_id=%s", (exam_id, student_id))
        existing = cur.fetchone()
        if existing:
            cur.execute("""
                UPDATE exam_assignments
                SET link_token=%s, status='Not Started', assign_time=NOW()
                WHERE id=%s
            """, (token, existing['id']))
        else:
            cur.execute("""
                INSERT INTO exam_assignments (exam_id, student_id, link_token, status, assign_time)
                VALUES (%s, %s, %s, 'Not Started', NOW())
            """, (exam_id, student_id, token))

    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Students assigned successfully.'}), 200

@app.route('/api/students/<int:student_id>/assignments', methods=['GET'])
def get_student_assignments(student_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 403

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT ea.id AS assignment_id, e.id AS exam_id, e.title, e.subject, e.date, ea.status
        FROM exam_assignments ea
        JOIN exams e ON ea.exam_id = e.id
        WHERE ea.student_id = %s
        ORDER BY e.date DESC
    """, (student_id,))
    assignments = cur.fetchall()
    cur.close()
    return jsonify(assignments)

@app.route('/api/students/<int:student_id>/assign-exam', methods=['POST'])
def assign_exam_to_student(student_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    exam_id = data.get('exam_id')
    if not exam_id:
        return jsonify({'error': 'No exam selected.'}), 400

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT id FROM exam_assignments WHERE exam_id=%s AND student_id=%s", (exam_id, student_id))
    existing = cur.fetchone()
    if existing:
        cur.close()
        return jsonify({'error': 'This student is already assigned to this exam.'}), 400

    import uuid
    token = str(uuid.uuid4())
    cur.execute("""
        INSERT INTO exam_assignments (exam_id, student_id, link_token, status, assign_time)
        VALUES (%s, %s, %s, 'Not Started', NOW())
    """, (exam_id, student_id, token))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Exam assigned to student!'})

@app.route('/api/exam_assignments/<int:assignment_id>', methods=['DELETE'])
def delete_assignment(assignment_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        cur = mysql.connection.cursor()
        # Delete all attempts first
        cur.execute("DELETE FROM exam_attempts WHERE assignment_id = %s", (assignment_id,))
        # Then delete the assignment
        cur.execute("DELETE FROM exam_assignments WHERE id = %s", (assignment_id,))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Assignment deleted successfully.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500




# -------------------- EXPORT EXAM QUESTIONS --------------------
@app.route('/api/exam/<int:exam_id>/questions/export', methods=['GET'])
def export_exam_questions(exam_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("""
            SELECT id, question_text, options, correct_answer
            FROM questions
            WHERE exam_id = %s
        """, (exam_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        # Convert options to JSON string if needed
        rows_list = []
        for row in rows:
            row = dict(row)
            if isinstance(row.get('options'), (list, dict)):
                row['options'] = json.dumps(row['options'])
            rows_list.append(row)

        # Write CSV
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['id', 'question_text', 'options', 'correct_answer'])
        writer.writeheader()
        writer.writerows(rows_list)
        csv_data = output.getvalue()
        output.close()

        response = make_response(csv_data)
        response.headers["Content-Disposition"] = f"attachment; filename=questions_exam_{exam_id}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response

    except Exception as e:
        traceback.print_exc()
        return {"error": "Failed to export questions. " + str(e)}, 500

# -------------------- SUBMIT EXAM --------------------
@app.route('/api/exams/<int:exam_id>/submit', methods=['POST'])
def submit_exam(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'student':
        return jsonify({'error': 'Unauthorized'}), 403

    token = request.args.get('token')
    data = request.get_json() or {}
    submitted_answers = data.get('answers', {})
    cheating = bool(data.get('cheating', False))
    student_id = session['user_id']

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Get assignment
        cur.execute("""
            SELECT id FROM exam_assignments
            WHERE exam_id=%s AND link_token=%s AND student_id=%s
            LIMIT 1
        """, (exam_id, token, student_id))
        assignment = cur.fetchone()
        if not assignment:
            cur.close()
            conn.close()
            return jsonify({'error': 'Invalid or expired exam link'}), 400
        assignment_id = assignment['id']

        # Get latest in-progress attempt
        cur.execute("""
            SELECT id FROM exam_attempts
            WHERE assignment_id=%s AND status='in_progress'
            ORDER BY start_time DESC LIMIT 1
        """, (assignment_id,))
        attempt = cur.fetchone()
        if not attempt:
            cur.close()
            conn.close()
            return jsonify({'error': 'No active attempt found'}), 400
        attempt_id = attempt['id']

        # Get all questions
        cur.execute("""
            SELECT id, question_type, correct_answer, marks
            FROM questions
            WHERE exam_id=%s
        """, (exam_id,))
        questions = cur.fetchall()

        per_question_marks, total_score, subjective_present = {}, 0, False

        def clean(val):
            if val is None: return ''
            return str(val).strip().lower()

        for q in questions:
            qid = str(q['id'])
            ans = submitted_answers.get(qid)
            if q['question_type'] == 'objective':
                if clean(ans) == clean(q['correct_answer']):
                    mark = q.get('marks', 1)
                    per_question_marks[qid] = mark
                    total_score += mark
                else:
                    per_question_marks[qid] = 0
            else:
                subjective_present = True
                per_question_marks[qid] = 0  # Teacher grading required

        grading_status = 'pending' if subjective_present else 'completed'

        # Update attempt
        cur.execute("""
            UPDATE exam_attempts
            SET answers=%s, score=%s, grading_status=%s,
                status='completed', cheating_detected=%s, end_time=NOW(),
                per_question_marks=%s
            WHERE id=%s
        """, (
            json.dumps(submitted_answers), total_score, grading_status,
            int(cheating), json.dumps(per_question_marks), attempt_id
        ))

        # Update assignment
        cur.execute("""
            UPDATE exam_assignments
            SET status='Submitted', cheating_submission=%s
            WHERE id=%s
        """, (int(cheating), assignment_id))

        conn.commit()
        cur.close()
        conn.close()

        message = (
            "Exam auto-submitted due to cheating detection!" if cheating else
            f"Exam submitted. Scored: {total_score}. Awaiting teacher grading." if subjective_present else
            f"Exam submitted successfully. Your score: {total_score}."
        )

        return jsonify({'message': message, 'cheating': 'Yes' if cheating else 'No'})

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# -------------------- AUTOSAVE EXAM --------------------
@app.route('/api/exams/<int:exam_id>/autosave', methods=['POST'])
def autosave_exam(exam_id):
    token = request.args.get('token')
    data = request.get_json() or {}
    answers = data.get('answers', {})

    if 'user_id' not in session or session.get('user_role') != 'student':
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE exam_attempts
            SET answers=%s
            WHERE assignment_id = (
                SELECT id FROM exam_assignments
                WHERE exam_id=%s AND link_token=%s AND student_id=%s
            ) AND status='in_progress'
            ORDER BY start_time DESC
            LIMIT 1
        """, (json.dumps(answers), exam_id, token, session['user_id']))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Autosaved successfully"})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# -------------------- GET EXAM RESULTS --------------------
@app.route('/api/exams/<int:exam_id>/results', methods=['GET'])
def get_exam_results(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("""
            SELECT u.id AS student_id, u.full_name, ea.status AS exam_status,
                   ea.id AS assignment_id, att.id AS attempt_id, att.score, att.grading_status, att.cheating_detected
            FROM exam_assignments ea
            JOIN users u ON ea.student_id = u.id
            LEFT JOIN exam_attempts att ON att.assignment_id = ea.id
            WHERE ea.exam_id = %s
        """, (exam_id,))
        results = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(results)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500



# -------------------- GRADE EXAM --------------------
@app.route('/api/exams/<int:exam_id>/grade/<int:student_id>', methods=['POST'])
def grade_exam(exam_id, student_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    grading_scores = data.get("grading_scores", {})

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("""
            SELECT ea.id AS assignment_id, att.id AS attempt_id
            FROM exam_assignments ea
            JOIN exam_attempts att ON att.assignment_id = ea.id
            WHERE ea.exam_id=%s AND ea.student_id=%s
            ORDER BY att.start_time DESC
            LIMIT 1
        """, (exam_id, student_id))
        attempt_data = cur.fetchone()

        if not attempt_data:
            cur.close()
            conn.close()
            return jsonify({"error": "Attempt not found"}), 404

        attempt_id = attempt_data['attempt_id']
        total_score = sum(grading_scores.values())
        grading_scores_json = json.dumps(grading_scores)

        cur.execute("""
            UPDATE exam_attempts
            SET score=%s, grading_status='completed', per_question_marks=%s
            WHERE id=%s
        """, (total_score, grading_scores_json, attempt_id))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "Grading submitted successfully", "new_score": total_score})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# -------------------- EXPORT RESULTS TO EXCEL --------------------
@app.route('/api/exams/<int:exam_id>/export_results_excel', methods=['GET'])
def export_results_excel(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("""
            SELECT u.full_name, ea.status, att.score, att.grading_status
            FROM exam_assignments ea
            JOIN users u ON ea.student_id = u.id
            LEFT JOIN exam_attempts att ON att.assignment_id = ea.id
            WHERE ea.exam_id = %s
        """, (exam_id,))
        results = cur.fetchall()
        cur.close()
        conn.close()

        df = pd.DataFrame(results)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Exam Results")

        output.seek(0)
        return send_file(output, download_name=f"exam_{exam_id}_results.xlsx", as_attachment=True)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# -------------------- GET STUDENT ANSWERS --------------------
@app.route('/api/exams/<int:exam_id>/answers/<int:student_id>')
def get_student_answers(exam_id, student_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("""
            SELECT att.answers, att.per_question_marks
            FROM exam_assignments ea
            JOIN exam_attempts att ON att.assignment_id = ea.id
            WHERE ea.exam_id = %s AND ea.student_id = %s
            ORDER BY att.start_time DESC
            LIMIT 1
        """, (exam_id, student_id))
        attempt = cur.fetchone()
        if not attempt:
            cur.close()
            conn.close()
            return jsonify([])

        answer_map = json.loads(attempt["answers"]) if attempt["answers"] else {}
        per_question_marks = json.loads(attempt["per_question_marks"]) if attempt.get("per_question_marks") else {}

        cur.execute("""
            SELECT id AS question_id, question_text, question_type, correct_answer, marks
            FROM questions WHERE exam_id = %s
        """, (exam_id,))
        questions = cur.fetchall()
        cur.close()
        conn.close()

        results = []
        for q in questions:
            qid_str = str(q['question_id'])
            results.append({
                "question_id": q['question_id'],
                "question_text": q['question_text'],
                "question_type": q['question_type'],
                "correct_answer": q['correct_answer'],
                "max_marks": q['marks'] or 1,
                "answer": answer_map.get(qid_str, "No Answer"),
                "marks_assigned": per_question_marks.get(qid_str, 0)
            })

        return jsonify(results)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# -------------------- EMAIL CONFIGURATION --------------------
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME='testoraofficial@gmail.com',
    MAIL_PASSWORD='hmcq wpoo pexe uxrs'
)
mail = Mail(app)

# -------------------- SEND EXAM ATTEMPT EMAIL --------------------
@app.route('/api/attempts/<int:attempt_id>/send_email', methods=['POST'])
def send_attempt_email(attempt_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("""
            SELECT ea.exam_id, ea.student_id, att.score
            FROM exam_attempts att
            JOIN exam_assignments ea ON att.assignment_id = ea.id
            WHERE att.id = %s
        """, (attempt_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return jsonify({"error": "No attempt found"}), 404

        exam_id = row['exam_id']
        student_id = row['student_id']
        score = row['score']

        cur.execute("SELECT title, subject FROM exams WHERE id = %s", (exam_id,))
        exam_row = cur.fetchone()
        exam_title = exam_row['title'] if exam_row and 'title' in exam_row else "Exam"
        subject = exam_row['subject'] if exam_row and 'subject' in exam_row else "N/A"

        cur.execute("SELECT email, full_name FROM users WHERE id = %s", (student_id,))
        user_row = cur.fetchone()
        cur.close()
        conn.close()

        if not user_row:
            return jsonify({"error": "No user found"}), 404

        email = user_row['email']
        name = user_row['full_name']

        msg = Message(
            subject=f"Your Exam Results: {exam_title} ({subject})",
            sender="testoraofficial@gmail.com",
            recipients=[email]
        )
        msg.body = (
            f"Dear {name},\n\n"
            f"We are pleased to inform you that the results for your recent examination are now available.\n\n"
            f"Exam: {exam_title}\n"
            f"Subject: {subject}\n"
            f"Score Obtained: {score}\n"
            f"If you have any questions regarding your result or require further clarification, please contact the academic office.\n\n"
            "Congratulations on your effort and dedication.\n\n"
            "Best regards,\n"
            "Testora Examination Team\n"
        )
        mail.send(msg)
        return jsonify({"message": "Email sent successfully"})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# -------------------- EXAM STATS --------------------
@app.route('/api/exams/<int:exam_id>/stats', methods=['GET'])
def get_exam_stats(exam_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute("""
            SELECT ea.score
            FROM exam_attempts ea
            JOIN exam_assignments ea2 ON ea.assignment_id = ea2.id
            WHERE ea2.exam_id = %s
        """, (exam_id,))
        scores = [row['score'] for row in cur.fetchall() if row['score'] is not None]

        cur.close()
        conn.close()

        if not scores:
            return jsonify({"error": "No scores available"}), 404

        return jsonify({
            "average": sum(scores) / len(scores),
            "highest": max(scores),
            "lowest": min(scores),
            "scores": scores
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500



# -------------------- GET ATTEMPT ANSWERS --------------------
@app.route('/api/attempts/<int:attempt_id>/answers', methods=['GET'])
def get_attempt_answers(attempt_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Fetch attempt and assignment info
        cur.execute("""
            SELECT att.answers, att.per_question_marks, ea.exam_id, att.student_id
            FROM exam_attempts att
            JOIN exam_assignments ea ON att.assignment_id = ea.id
            WHERE att.id = %s
        """, (attempt_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return jsonify([])

        exam_id = row["exam_id"]
        answers = json.loads(row["answers"]) if row["answers"] else {}
        per_question_marks = json.loads(row.get("per_question_marks") or "{}")

        # Fetch questions and exam title
        cur.execute("""
            SELECT id AS question_id, question_text, question_type, correct_answer, marks
            FROM questions
            WHERE exam_id = %s
        """, (exam_id,))
        questions = cur.fetchall()

        cur.execute("SELECT title FROM exams WHERE id = %s", (exam_id,))
        exam_row = cur.fetchone()
        exam_title = exam_row["title"] if exam_row else "Unknown"

        cur.close()
        conn.close()

        detailed_answers = []
        for q in questions:
            qid_str = str(q['question_id'])
            detailed_answers.append({
                "question_id": q['question_id'],
                "question_text": q['question_text'],
                "question_type": q['question_type'],
                "correct_answer": q['correct_answer'],
                "max_marks": q['marks'],
                "answer": answers.get(qid_str, "No Answer"),
                "marks_assigned": per_question_marks.get(qid_str, 0)
            })

        return jsonify({
            "exam_title": exam_title,
            "exam_id": exam_id,
            "student_id": row["student_id"],
            "answers": detailed_answers
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# -------------------- GRADE ATTEMPT --------------------
@app.route('/api/attempts/<int:attempt_id>/grade', methods=['POST'])
def grade_attempt(attempt_id):
    if 'user_id' not in session or session.get('user_role') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    grading_scores = data.get("grading_scores", {})  # Only subjective question ids

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Fetch original marks
        cur.execute("SELECT per_question_marks FROM exam_attempts WHERE id = %s", (attempt_id,))
        row = cur.fetchone()
        original_marks = json.loads(row['per_question_marks']) if row and row['per_question_marks'] else {}

        # Update only subjective marks
        for k, v in grading_scores.items():
            original_marks[str(k)] = v  # Preserve objective marks

        total_score = sum(original_marks.values())
        grading_json = json.dumps(original_marks)

        cur.execute("""
            UPDATE exam_attempts
            SET score = %s,
                grading_status = 'completed',
                per_question_marks = %s
            WHERE id = %s
        """, (total_score, grading_json, attempt_id))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "Grades saved", "total_score": total_score})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# -------------------- LOGOUT --------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('serve_homepage'))

# -------------------- RUN APP --------------------
if __name__ == '__main__':
    app.run(debug=True)
