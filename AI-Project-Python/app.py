import os
import base64
import io
import json
import random
import socket
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from pymongo import MongoClient
from bson import ObjectId
from PIL import Image, ImageOps
import numpy as np
from urllib.parse import quote_plus
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
import tempfile
import cv2
import werkzeug.utils

# --- Local Utility Import ---
import face_utils

# --- App Initialization ---
app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = 'a_super_secret_string_that_is_long_and_random'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

# Google OAuth Configuration
app.config['add yours google client'] = '393712926688-gus1222o4de1vss07ebdjrknlh533f53.apps.googleusercontent.com'
app.config['secret code'] = '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'

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['username'] = 'missingpersonfinder6@gmail.com'
app.config['password'] = 'rgtz sqnf plls jsur'  # IMPORTANT: Use a 16-digit Google App Password here
app.config['MAil id'] = ("FaceTrace AI", "missingpersonfinder6@gmail.com")

mail = Mail(app)
oauth = OAuth(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- MongoDB Connection ---
DB_USERNAME = 'database name'
DB_PASSWORD = 'database password'
DB_CLUSTER_URL = "cluster0.fe3yf6z.mongodb.net"
DB_NAME = "lost_and_found_db"

escaped_username = quote_plus(DB_USERNAME)
escaped_password = quote_plus(DB_PASSWORD)
MONGO_CONNECTION_STRING = f"mongodb+srv://{escaped_username}:{escaped_password}@{DB_CLUSTER_URL}/?retryWrites=true&w=majority&appName=Cluster0"

client = MongoClient(MONGO_CONNECTION_STRING)
db = client[DB_NAME]
cases_collection = db['cases']
users_collection = db['users']
sightings_collection = db['sightings']

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# --- User Model and Loader ---
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.password_hash = user_data.get('password')
        self.email = user_data.get('email', user_data['username'])

    @staticmethod
    def get(user_id):
        user_data = users_collection.find_one({'_id': ObjectId(user_id)})
        return User(user_data) if user_data else None

    @staticmethod
    def find_by_username(username):
        return users_collection.find_one({'username': username})

    @staticmethod
    def find_by_email(email):
        return users_collection.find_one({'email': email})


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


# --- Helper Functions ---
def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def cleanup_old_found_cases():
    three_days_ago = datetime.now() - timedelta(days=3)
    cases_collection.delete_many({'status': 'found', 'foundDate': {'$lt': three_days_ago.isoformat()}})


def create_initial_user():
    if users_collection.count_documents({}) == 0:
        hashed_password = generate_password_hash('admin123', method='pbkdf2:sha256')
        users_collection.insert_one({'username': 'admin', 'password': hashed_password, 'email': 'admin@example.com'})


def send_otp_email(user_email, otp):
    msg = Message('Your Password Reset OTP', recipients=[user_email])
    msg.body = f'Your OTP for password reset is: {otp}. It is valid for 10 minutes.'
    mail.send(msg)


def send_sighting_notification_email(recipient_email, case_name, sighting_details, reporter_name="An anonymous user"):
    msg = Message(f"New Sighting Reported for {case_name}", recipients=[recipient_email])
    msg.body = f"A new sighting has been reported for '{case_name}' by {reporter_name}.\n\nDetails: {sighting_details['message']}\nLocation: {sighting_details['location']}\n\nPlease log in to view more information."
    mail.send(msg)


def send_match_notification_email(recipient_email, case_id, case_name, location_details, image_bytes, reporter_info):
    subject = f"Potential Match Found for {case_name}"
    token_data = {'case_id': str(case_id), 'location': location_details}
    token = s.dumps(token_data, salt='match-confirmation-salt')
    confirm_link = url_for('confirm_match', token=token, _external=True)
    msg = Message(subject, recipients=[recipient_email])
    maps_link = f"http://googleusercontent.com/maps/google.com/1{location_details['lat']},{location_details['lon']}"

    reporter_html = f"<p>This match was reported by: <b>{reporter_info['name']}</b>.<br>You can contact them via email at: <b>{reporter_info['email']}</b></p>" if reporter_info else "<p>This match was reported by an anonymous user.</p>"

    msg.html = f"""
    <h3>Potential Match Found</h3>
    <p>A photo analyzed has resulted in a potential match for the case of <b>{case_name}</b>.</p>
    {reporter_html}
    <p><b>Sighting Location:</b> {location_details.get('address', 'Not available')}</p>
    <p><b><a href="{maps_link}">Click here to view the location on Google Maps</a></b></p>
    <hr>
    <p>If you believe this is a correct match, please confirm by clicking the button below. This will update the case status to "Found".</p>
    <a href="{confirm_link}" style="display: inline-block; padding: 10px 20px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px;">Confirm Match & Mark as Found</a>
    <p><small>If you did not expect this, please ignore this email.</small></p>
    """

    msg.attach("sighting_photo.jpg", "image/jpeg", image_bytes)
    mail.send(msg)


def send_new_case_alert_to_all_users(case_details, image_bytes):
    all_users = users_collection.find({})
    recipient_emails = [user['email'] for user in all_users if 'email' in user]

    if not recipient_emails:
        print("No users found to send new case alert.")
        return

    subject = f"Missing Person Alert in {case_details['lastSeen']}"
    case_url = url_for('case_detail', case_id=case_details['id'], _external=True)

    cash_reward_html = ''
    if case_details.get('cashReward') and case_details['cashReward'] > 0:
        reward_amount = "{:,.0f}".format(case_details['cashReward'])
        cash_reward_html = f"""
        <div style="text-align: center; margin: 20px 0; padding: 15px; background-color: #28a745; border-radius: 8px; color: white;">
            <h2 style="margin: 0; font-size: 22px;">CASH REWARD: ₹{reward_amount}</h2>
            <p style="margin: 5px 0 0 0;">A reward is being offered for information leading to their safe return.</p>
        </div>
        """

    msg = Message(subject, recipients=['donotreply@missingpersonfinder.com'], bcc=recipient_emails)

    msg.html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; color: #333; }}
            .container {{ padding: 20px; border: 1px solid #ddd; border-radius: 8px; max-width: 600px; margin: auto; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .header {{ font-size: 24px; font-weight: bold; color: #d9534f; text-align: center; }}
            .highlight {{ background-color: #fcf8e3; padding: 10px; border-left: 5px solid #f0ad4e; margin: 15px 0; }}
            .button {{ display: inline-block; padding: 12px 24px; background-color: #0275d8; color: white; text-decoration: none; border-radius: 5px; text-align: center; }}
            .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #777; }}
        </style>
    </head>
    <body>
        <div class="container">
            <p class="header">MISSING PERSON ALERT</p>
            <hr>
            <p>A new case has been reported. Please be on the lookout for the following individual:</p>

            <h3 style="text-align: center; font-size: 20px;">{case_details['name']}</h3>
            <ul>
                <li><strong>Age:</strong> {case_details['age']}</li>
                <li><strong>Gender:</strong> {case_details['gender']}</li>
                <li class="highlight"><strong>Last Seen Location:</strong> {case_details['lastSeen']}</li>
                <li><strong>Distinguishing Features:</strong> {case_details['distinguishingFeatures']}</li>
            </ul>

            {cash_reward_html}

            <p>A photo is attached to this email.</p>

            <p style="text-align: center;">If you have any information, please click the button below to view the full case details and report a sighting.</p>
            <p style="text-align: center; margin: 20px 0;">
                <a href="{case_url}" class="button">View Case Details</a>
            </p>
            <div class="footer">
                <p>Thank you for your help in keeping our community safe.</p>
            </div>
        </div>
    </body>
    </html>
    """
    msg.attach(f"{case_details['name']}.jpg", "image/jpeg", image_bytes)
    mail.send(msg)


# --- Google OAuth Routes ---
google = oauth.register(
    name='google',
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
)


@app.route('/google-login')
def google_login():
    redirect_uri = url_for('google_auth', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/google-auth')
def google_auth():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    user_email = user_info['email']
    user_name = user_info.get('name', user_email.split('@')[0])
    user_data = User.find_by_email(user_email)
    if not user_data:
        new_user = {'username': user_name, 'email': user_email, 'password': None, 'provider': 'google'}
        users_collection.insert_one(new_user)
        user_data = new_user

    user_obj = User(user_data)
    login_user(user_obj, remember=True)

    flash('Logged in successfully with Google!', 'success')
    return redirect(url_for('main_menu'))


# --- Standard Auth & Profile Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main_menu'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_data = User.find_by_username(username)
        if user_data and user_data.get('password') and check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user, remember=True)
            return redirect(url_for('main_menu'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main_menu'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        if User.find_by_username(username) or User.find_by_email(email):
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password
        })
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main_menu'))


# --- Password Reset Routes ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.find_by_email(email)
        if user:
            otp = random.randint(100000, 999999)
            session['reset_otp'] = otp
            session['otp_timestamp'] = datetime.now().timestamp()
            session['reset_email'] = user['email']
            try:
                send_otp_email(user['email'], otp)
                flash('An OTP has been sent to your email.', 'info')
                return redirect(url_for('verify_otp'))
            except Exception as e:
                flash(f'Failed to send email. Error: {e}', 'danger')
        else:
            flash('Email address not found.', 'danger')
    return render_template('forgot_password.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        otp_timestamp = session.get('otp_timestamp')
        if not otp_timestamp or (datetime.now().timestamp() - otp_timestamp) > 600:  # 10 minutes
            flash('OTP has expired. Please request a new one.', 'danger')
            session.clear()
            return redirect(url_for('forgot_password'))
        if user_otp and int(user_otp) == session.get('reset_otp'):
            session['otp_verified'] = True
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    return render_template('verify_otp.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('otp_verified'):
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html')
        email = session['reset_email']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        users_collection.update_one({'email': email}, {'$set': {'password': hashed_password}})
        session.clear()
        flash('Your password has been updated successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')


# --- Main Application & Case Routes ---
@app.route('/')
def main_menu():
    cleanup_old_found_cases()  # Run cleanup task
    all_cases = list(cases_collection.find())
    missing_cases = []
    found_cases = []

    for case in all_cases:
        case['id'] = str(case['_id'])
        if case.get('status') == 'active':
            missing_cases.append(case)
        else:
            found_cases.append(case)

    return render_template('main_menu.html', missing_cases=missing_cases, found_cases=found_cases)


@app.route('/manage')
@login_required
def manage_cases():
    user_cases_cursor = cases_collection.find({'createdBy': current_user.id})
    user_cases = []
    for case in user_cases_cursor:
        case['id'] = str(case['_id'])
        if case.get('status') == 'active' and case.get('missingSince'):
            try:
                missing_date = datetime.strptime(case['missingSince'], '%Y-%m-%d')
                case['days_missing'] = (datetime.now() - missing_date).days
            except (ValueError, TypeError):
                case['days_missing'] = 0
        else:
            case['days_missing'] = 0
        user_cases.append(case)
    return render_template('manage_cases.html', cases=user_cases)


@app.route('/profile')
@login_required
def profile():
    user_cases_cursor = cases_collection.find({'createdBy': current_user.id})
    user_cases = []
    for case in user_cases_cursor:
        case['id'] = str(case['_id'])
        user_cases.append(case)
    return render_template('profile.html', cases=user_cases)


@app.route('/case/<case_id>')
def case_detail(case_id):
    case = cases_collection.find_one({'_id': ObjectId(case_id)})
    if not case:
        return "Case not found", 404
    case['id'] = str(case['_id'])
    case_sightings = list(sightings_collection.find({'caseId': case_id}))
    return render_template('case_detail.html', case=case, sightings=case_sightings)


@app.route('/found_case_details/<case_id>')
def found_case_details(case_id):
    case = cases_collection.find_one({'_id': ObjectId(case_id)})
    if not case or case.get('status') != 'found':
        flash('This case is not marked as found or does not exist.', 'danger')
        return redirect(url_for('main_menu'))

    case['id'] = str(case['_id'])

    # Calculate when the case will be deleted
    found_date = datetime.fromisoformat(case['foundDate'])
    deletion_date = found_date + timedelta(days=3)
    case['deletion_date_str'] = deletion_date.strftime('%Y-%m-%d %H:%M:%S')

    return render_template('found_case_detail.html', case=case)


@app.route('/case/<case_id>/poster')
def print_poster(case_id):
    case = cases_collection.find_one({'_id': ObjectId(case_id)})
    if not case:
        return "Case not found", 404

    host_ip = get_host_ip()
    network_url = f"http://{host_ip}:5000{url_for('case_detail', case_id=case_id)}"

    return render_template('poster_template.html', case=case, network_url=network_url)


@app.route('/analyze')
def analyze_sighting():
    return render_template('analyze.html')


@app.route('/confirm_match/<token>')
def confirm_match(token):
    try:
        data = s.loads(token, salt='match-confirmation-salt', max_age=86400)  # 1 day validity
        case_id = data['case_id']
        location = data['location']

        result = cases_collection.update_one(
            {'_id': ObjectId(case_id)},
            {'$set': {
                'status': 'found',
                'foundDate': datetime.now().isoformat(),
                'foundLocation': location
            }}
        )

        if result.matched_count > 0:
            flash('Match confirmed! The case status has been updated to "Found".', 'success')
            return redirect(url_for('found_case_details', case_id=case_id))
        else:
            flash('Could not find the specified case.', 'danger')

    except Exception as e:
        flash('The confirmation link is invalid or has expired.', 'danger')

    return redirect(url_for('main_menu'))


# --- API Endpoints ---
@app.route('/api/add_sighting/<case_id>', methods=['POST'])
def add_sighting(case_id):
    try:
        data = request.json
        sighting_details = {
            'message': data.get('message'),
            'location': data.get('location')
        }
        if not sighting_details['message'] or not sighting_details['location']:
            return jsonify({'success': False, 'message': 'Message and location are required.'}), 400

        reporter_name = current_user.username if current_user.is_authenticated else "An anonymous user"

        new_sighting = {
            'caseId': case_id,
            'message': sighting_details['message'],
            'location': sighting_details['location'],
            'timestamp': datetime.now().isoformat(),
            'reportedBy': reporter_name
        }
        sightings_collection.insert_one(new_sighting)

        case = cases_collection.find_one({'_id': ObjectId(case_id)})
        if case and 'createdBy' in case:
            case_owner = users_collection.find_one({'_id': ObjectId(case['createdBy'])})
            if case_owner and 'email' in case_owner:
                send_sighting_notification_email(case_owner['email'], case['name'], sighting_details, reporter_name)

        return jsonify({'success': True, 'message': 'Sighting reported successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'An internal error occurred.'}), 500


@app.route('/api/process_photo', methods=['POST'])
@login_required
def process_photo():
    try:
        if 'photo' not in request.files:
            return jsonify({'success': False, 'message': 'No photo provided.'}), 400

        photo_file = request.files['photo']
        image_bytes = photo_file.read()
        image = Image.open(io.BytesIO(image_bytes))

        image = ImageOps.exif_transpose(image)
        if image.mode != 'RGB':
            image = image.convert('RGB')

        max_size = 1024
        if image.width > max_size or image.height > max_size:
            image.thumbnail((max_size, max_size))

        output_buffer = io.BytesIO()
        image.save(output_buffer, format="JPEG")
        image_bytes_corrected = output_buffer.getvalue()

        image_np = np.array(image)
        descriptor = face_utils.get_face_descriptor(image_np)

        if descriptor is None:
            return jsonify(
                {'success': False, 'message': 'Could not find a clear face. Please use a different photo.'}), 400
        if isinstance(descriptor, str) and descriptor == 'multiple':
            return jsonify({'success': False,
                            'message': 'Multiple faces detected. Please upload a photo with only one person.'}), 400

        photo_base64 = base64.b64encode(image_bytes_corrected).decode('utf-8')
        photo_url = f"data:image/jpeg;base64,{photo_base64}"

        return jsonify({
            'success': True,
            'photoURL': photo_url,
            'descriptor': descriptor.tolist()
        })
    except Exception as e:
        print(f"Error processing photo: {e}")
        return jsonify({'success': False, 'message': 'An internal error occurred during photo processing.'}), 500


@app.route('/api/add_case', methods=['POST'])
@login_required
def add_case():
    try:
        name = request.form['name']
        photo_url = request.form['photoURL']
        descriptor_str = request.form['descriptor']

        if not all([name, photo_url, descriptor_str]):
            return jsonify({'success': False, 'message': 'Missing required data.'}), 400

        header, encoded = photo_url.split(",", 1)
        image_bytes_corrected = base64.b64decode(encoded)

        new_case_data = {
            'name': name, 'age': request.form['age'], 'gender': request.form['gender'],
            'lastSeen': request.form['lastSeen'], 'contact': request.form['contact'],
            'missingSince': request.form['missingSince'], 'status': 'active',
            'distinguishingFeatures': request.form['distinguishingFeatures'],
            'cashReward': int(request.form.get('cashReward')) if request.form.get('cashReward', '').isdigit() else None,
            'photoURL': photo_url,
            'descriptor': json.loads(descriptor_str),
            'createdBy': current_user.id
        }
        result = cases_collection.insert_one(new_case_data)

        new_case_data['id'] = str(result.inserted_id)
        send_new_case_alert_to_all_users(new_case_data, image_bytes_corrected)

        return jsonify({'success': True, 'message': f'Case for {name} added successfully!'})
    except Exception as e:
        print(f"Error adding case: {e}")
        return jsonify({'success': False, 'message': 'An internal error occurred.'}), 500


# In app.py, REPLACE the analyze_photo function with this one.

# In app.py, REPLACE the analyze_photo function with this one.

# In app.py, REPLACE the analyze_photo function with this one.

@app.route('/api/analyze_photo', methods=['POST'])
def analyze_photo():
    try:
        # --- NEW: Check the source of the request ---
        source = request.form.get('source', 'upload')  # Defaults to 'upload' if not provided

        photo_file = request.files['photo']
        lat = request.form.get('lat')
        lon = request.form.get('lon')
        address = request.form.get('address', 'Location not provided')

        # ... (the rest of the image processing logic is the same) ...
        image_bytes = photo_file.read()
        image = Image.open(io.BytesIO(image_bytes))
        image = ImageOps.exif_transpose(image)
        if image.mode != 'RGB': image = image.convert('RGB')

        max_width = 800
        if image.width > max_width:
            ratio = max_width / float(image.width)
            new_height = int(float(image.height) * float(ratio))
            image = image.resize((max_width, new_height), Image.LANCZOS)

        output_buffer = io.BytesIO()
        image.save(output_buffer, format="JPEG")
        image_bytes_resized = output_buffer.getvalue()
        image_np = np.array(image)

        resized_width, resized_height = image.width, image.height

        active_cases = list(cases_collection.find({'status': 'active'}))
        if not active_cases:
            return jsonify({'success': False, 'message': 'No active cases in the database.'}), 400

        for case in active_cases:
            case['id'] = str(case['_id'])

        known_descriptors = [np.array(case['descriptor']) for case in active_cases]
        known_names = [case['name'] for case in active_cases]

        results = face_utils.find_matches_in_image(image_np, known_descriptors, known_names)

        matched_case_details = []
        sighting_location_details = {"lat": lat, "lon": lon, "address": address}
        reporter_info = None
        if current_user.is_authenticated:
            reporter_info = {"name": current_user.username, "email": current_user.email}

        if results['matches_found'] > 0:
            matched_name_strings = {res['name'] for res in results['match_results'] if res['name'] != 'Unknown'}
            individual_names = set(
                name.strip() for name_string in matched_name_strings for name in name_string.split(','))

            for name in individual_names:
                for case in active_cases:
                    if case['name'] == name:
                        case_to_add = case.copy()

                        # --- NEW: Only send email if it's a single photo upload ---
                        if source == 'upload':
                            owner_id = case_to_add.get('createdBy')
                            if owner_id:
                                owner = users_collection.find_one({'_id': ObjectId(owner_id)})
                                if owner and 'email' in owner and lat and lon:
                                    send_match_notification_email(
                                        recipient_email=owner['email'],
                                        case_id=case_to_add['id'],
                                        case_name=case_to_add['name'],
                                        location_details=sighting_location_details,
                                        image_bytes=image_bytes_resized,
                                        reporter_info=reporter_info
                                    )

                        case_to_add.pop('_id', None)
                        matched_case_details.append(case_to_add)

        results['image_width'] = resized_width
        results['image_height'] = resized_height

        response_data = {
            'success': True,
            'image_data': f"data:image/jpeg;base64,{base64.b64encode(image_bytes_resized).decode('utf-8')}",
            'results': results,
            'matched_profiles': matched_case_details,
        }
        return jsonify(response_data)
    except Exception as e:
        print(f"Error analyzing photo: {e}")
        return jsonify({'success': False, 'message': 'An internal error occurred.'}), 500


@app.route('/api/analyze_video', methods=['POST'])
def analyze_video():
    if 'video' not in request.files:
        return jsonify({'success': False, 'message': 'No video provided.'}), 400
    video_file = request.files['video']
    lat = request.form.get('lat')
    lon = request.form.get('lon')
    address = request.form.get('address', 'Location not provided')

    with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as temp_video:
        video_file.save(temp_video.name)
        temp_video_path = temp_video.name

    try:
        active_cases = list(cases_collection.find({'status': 'active'}))
        if not active_cases:
            return jsonify({'success': False, 'message': 'No active cases in the database.'}), 400
        for case in active_cases:
            case['id'] = str(case['_id'])
        known_descriptors = [np.array(case['descriptor']) for case in active_cases]
        known_names = [case['name'] for case in active_cases]

        cap = cv2.VideoCapture(temp_video_path)
        fps = cap.get(cv2.CAP_PROP_FPS) or 30
        frame_interval = int(fps)
        found_matches = {}
        frame_count = 0

        sighting_location_details = {"lat": lat, "lon": lon, "address": address}
        reporter_info = None
        if current_user.is_authenticated:
            reporter_info = {"name": current_user.username, "email": current_user.email}

        while cap.isOpened():
            ret, frame = cap.read()
            if not ret: break
            if frame_count % frame_interval == 0:
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                results = face_utils.find_matches_in_image(rgb_frame, known_descriptors, known_names)
                if results['matches_found'] > 0:
                    current_timestamp = round(frame_count / fps, 2)
                    matched_name_strings = {res['name'] for res in results['match_results'] if res['name'] != 'Unknown'}
                    individual_names = set(
                        name.strip() for name_string in matched_name_strings for name in name_string.split(','))

                    # --- MODIFIED LOGIC BLOCK in analyze_video ---
                    for name in individual_names:
                        # This block only runs the FIRST time a specific name is found
                        if name not in found_matches:
                            matching_case = next((c for c in active_cases if c['name'] == name), None)
                            if matching_case:
                                # --- ADDED: Capture a snapshot of the first match frame ---
                                snapshot_base64 = None
                                is_success, buffer = cv2.imencode(".jpg", frame)
                                if is_success:
                                    snapshot_bytes = io.BytesIO(buffer).read()
                                    snapshot_base64 = f"data:image/jpeg;base64,{base64.b64encode(snapshot_bytes).decode('utf-8')}"

                                # Add the person and their snapshot to our results dictionary
                                matching_case_copy = matching_case.copy()
                                matching_case_copy.pop('_id', None)
                                found_matches[name] = {
                                    'profile': matching_case_copy,
                                    'timestamps': [],
                                    'snapshot': snapshot_base64  # The snapshot is now part of the result
                                }

                        # This part adds the timestamp for every match (no change here)
                        if name in found_matches and current_timestamp not in found_matches[name]['timestamps']:
                            found_matches[name]['timestamps'].append(current_timestamp)
            frame_count += 1
        cap.release()
    finally:
        if os.path.exists(temp_video_path):
            os.remove(temp_video_path)

    final_results = list(found_matches.values())
    return jsonify({'success': True, 'results': final_results})


# --- NEW ENDPOINT FOR MANUAL NOTIFICATION ---
# In app.py, REPLACE the entire notify_owner function with this one.

# In app.py, REPLACE the entire notify_owner function with this one.

@app.route('/api/notify_owner', methods=['POST'])
@login_required
def notify_owner():
    try:
        data = request.json
        case_id = data.get('case_id')
        location_details = data.get('location_details')
        snapshot_data = data.get('snapshot_data')

        if not all([case_id, location_details, snapshot_data]):
            return jsonify({'success': False, 'message': 'Missing required data.'}), 400

        case = cases_collection.find_one({'_id': ObjectId(case_id)})
        if not case:
            return jsonify({'success': False, 'message': 'Case could not be found.'}), 404

        owner_id = case.get('createdBy')
        if not owner_id:
            return jsonify({'success': False, 'message': 'This case has no owner, cannot send notification.'}), 400

        owner = users_collection.find_one({'_id': ObjectId(owner_id)})
        if not owner or 'email' not in owner:
            return jsonify({'success': False, 'message': 'Could not find the case owner\'s email address.'}), 404

        header, encoded = snapshot_data.split(",", 1)
        image_bytes = base64.b64decode(encoded)

        reporter_info = {"name": current_user.username, "email": current_user.email}

        # --- THIS LINE IS NOW CORRECTED ---
        send_match_notification_email(
            recipient_email=owner['email'],
            case_id=case_id,
            case_name=case['name'],
            location_details=location_details,
            image_bytes=image_bytes,
            reporter_info=reporter_info
        )

        return jsonify({'success': True, 'message': f"Notification sent to the owner of case '{case['name']}'."})

    except Exception as e:
        print(f"Error in notify_owner: {e}")
        return jsonify({'success': False, 'message': 'An internal server error occurred.'}), 500


@app.route('/api/get_case/<case_id>', methods=['GET'])
@login_required
def get_case(case_id):
    try:
        case = cases_collection.find_one({'_id': ObjectId(case_id)})
        if not case or case.get('createdBy') != current_user.id:
            return jsonify({'success': False, 'message': 'Unauthorized.'}), 403
        case['_id'] = str(case['_id'])
        return jsonify(case)
    except Exception:
        return jsonify({'success': False, 'message': 'An internal error occurred.'}), 500


@app.route('/api/update_case/<case_id>', methods=['POST'])
@login_required
def update_case(case_id):
    try:
        case = cases_collection.find_one({'_id': ObjectId(case_id)})
        if not case or case.get('createdBy') != current_user.id:
            return jsonify({'success': False, 'message': 'Unauthorized.'}), 403

        cash_reward = request.form.get('cashReward')
        update_data = {
            'name': request.form['name'], 'age': request.form['age'],
            'gender': request.form['gender'], 'lastSeen': request.form['lastSeen'],
            'contact': request.form['contact'], 'missingSince': request.form['missingSince'],
            'distinguishingFeatures': request.form['distinguishingFeatures'],
            'cashReward': int(cash_reward) if cash_reward and cash_reward.isdigit() else None
        }

        if 'photoURL' in request.form and 'photoURL' and 'descriptor' in request.form and request.form['descriptor']:
            update_data['photoURL'] = request.form['photoURL']
            update_data['descriptor'] = json.loads(request.form['descriptor'])

        cases_collection.update_one({'_id': ObjectId(case_id)}, {'$set': update_data})
        return jsonify({'success': True, 'message': 'Case updated.'})
    except Exception as e:
        print(f"Error updating case: {e}")
        return jsonify({'success': False, 'message': 'An internal error occurred.'}), 500


if __name__ == '__main__':
    create_initial_user()
    app.run(host='0.0.0.0', port=5000, debug=True)
