from flask import Flask, render_template, request, redirect, flash, url_for, session
import pandas as pd
import os
import camelot
import io
from pymongo import MongoClient
import json
from google_auth_oauthlib.flow import Flow
import google.oauth2.credentials
from googleapiclient.discovery import build
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
import math
from datetime import datetime, timedelta
from datetime import datetime, date, timedelta
import fitz
import re
import matplotlib

app = Flask(__name__)
app.secret_key = 'asdfghjkl'

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']

client = MongoClient("mongodb+srv://10caditiverma:ZGzxoFRG8YEEpfz4@cluster1.jvmwija.mongodb.net/?retryWrites=true&w=majority&appName=Cluster1")
db = client['attendance_app_db']
users_collection = db['users']
timetables_collection = db['timetables']
settings_collection = db['settings']
attendance_log_collection = db['attendance_log']
events_collection = db['events']


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data["username"]

@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({"_id": ObjectId(user_id)})
    return User(user_data) if user_data else None


def get_day_order(day_name):
    order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    try:
        return order.index(day_name)
    except ValueError:
        return len(order)

from collections import defaultdict

def parse_timetable_from_pdf(pdf_stream):
    doc = fitz.open(stream=pdf_stream, filetype="pdf")
    page = doc[0] # Assume timetable is on the first page

    # Get all text blocks with their coordinates (x0, y0, x1, y1, text, ...)
    blocks = page.get_text("blocks")
    
    # Identify the y-coordinate of the header row (days of the week)
    header_y = 0
    for block in blocks:
        text = block[4]
        if "MON" in text or "TUE" in text or "WED" in text:
            header_y = block[1] # y0 coordinate of the header block
            break

    if header_y == 0:
        return None # Could not find the header

    # Separate header blocks from content blocks
    header_blocks = sorted([b for b in blocks if abs(b[1] - header_y) < 10], key=lambda b: b[0])
    content_blocks = [b for b in blocks if b[1] > header_y]

    # Map column x-coordinates to day names from the header
    days_map = {
        'MON': 'Monday', 'TUE': 'Tuesday', 'WED': 'Wednesday', 
        'THU': 'Thursday', 'FRI': 'Friday', 'SAT': 'Saturday', 'SUN': 'Sunday'
    }
    column_to_day = {}
    for block in header_blocks:
        x0, text = block[0], block[4]
        for short_day, full_day in days_map.items():
            if short_day in text:
                # Find the center of the day's column
                column_to_day[(x0 + block[2]) / 2] = full_day

    # Sort columns by their x-position
    sorted_columns = sorted(column_to_day.keys())

    timetable_data = []
    
    # Group content blocks into their respective columns
    for block in content_blocks:
        bx0, text = block[0], block[4]
        # Find which column this block belongs to by finding the closest column center
        closest_col = min(sorted_columns, key=lambda c: abs(c - bx0))
        day = column_to_day[closest_col]

        # Parse the text inside the block
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        if lines and '-' in lines[0] and ':' in lines[0]:
            try:
                time_range = lines[0]
                subject = lines[1]
                
                time_parts = time_range.split('-')
                start_time = time_parts[0].strip()
                end_time = time_parts[1].strip()
                
                timetable_data.append([day, start_time, end_time, subject])
            except (IndexError, ValueError):
                continue

    if not timetable_data:
        return None

    final_df = pd.DataFrame(timetable_data, columns=['Day', 'Start Time', 'End Time', 'Subject'])
    return final_df

@app.route('/debug_pdf', methods=['GET', 'POST'])
@login_required
def debug_pdf():
    if request.method == 'POST':
        if 'file' not in request.files or not request.files['file'].filename:
            flash('No file selected.', 'error')
            return redirect(url_for('debug_pdf'))
        
        file = request.files['file']
        if not file.filename.lower().endswith('.pdf'):
            flash('Please upload a PDF file.', 'error')
            return redirect(url_for('debug_pdf'))

        try:
            os.makedirs("uploads", exist_ok=True)
            os.makedirs("static", exist_ok=True)
            filepath = os.path.join("uploads", "temp_debug.pdf")
            file.save(filepath)

            # Use the correct flavor for a lined PDF table
            tables = camelot.read_pdf(filepath, pages='all', flavor='lattice')

            if not tables:
                flash("Camelot could not find any tables in this PDF.", "error")
                return redirect(url_for('debug_pdf'))

            print("--- CAMELOT DEBUG OUTPUT ---")
            print(tables[0].df) 
            print("--------------------------")
            
            try:
                plot_path = os.path.join("static", "debug_plot.png")
                camelot.plot(tables[0], kind='grid').savefig(plot_path)
                return render_template('debug_plot.html', plot_url=url_for('static', filename='debug_plot.png', t=datetime.now().timestamp()))
            except Exception as plot_error:
                print(f"PLOTTING FAILED: {plot_error}")
                flash(f"Table was found, but plotting failed: {plot_error}.", "danger")
                return redirect(url_for('debug_pdf'))

        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "danger")
            return redirect(url_for('debug_pdf'))
            
    return render_template('debug_pdf.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        existing_user = users_collection.find_one({'username': username})

        if existing_user:
            flash('Username already exists.', 'warning')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        users_collection.insert_one({'username': username, 'password_hash': hashed_password})
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/authorize')
@login_required
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)


@app.route('/oauth2callback')
@login_required
def oauth2callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    flash('Authentication successful!', 'success')
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = users_collection.find_one({'username': request.form.get('username')})
        if user and check_password_hash(user['password_hash'], request.form.get('password')):
            user_obj = User(user)
            login_user(user_obj)
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('credentials', None) # Clear Google credentials on logout
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@app.route('/')
@login_required 
def index():
    user_timetable = timetables_collection.find_one({
        "user_id": ObjectId(current_user.id)
    })

    if user_timetable:
        return render_template('dashboard.html')
    else:
        return render_template('timetable.html')

@app.route('/upload_timetable', methods=['POST'])
@login_required
def upload_timetable():
    if 'file' not in request.files or request.files['file'].filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('index'))

    file = request.files['file']
    filename = file.filename

    try:
        df = None
        if filename.lower().endswith('.csv'):
            df = pd.read_csv(file)
        elif filename.lower().endswith('.pdf'):
            pdf_content = file.read()
            df = parse_timetable_from_pdf(pdf_content)
            if df is None:
                flash('Could not find a valid timetable structure in the PDF.', 'error')
                return redirect(url_for('index'))
        else:
            flash('Invalid file type. Please upload a CSV or PDF.', 'error')
            return redirect(url_for('index'))

        required_columns = ['Day', 'Start Time', 'End Time', 'Subject']
        if not all(col in df.columns for col in required_columns):
            flash(f"File must contain columns: {', '.join(required_columns)}", 'error')
            return redirect(url_for('index'))

        timetable_grid = {}
        unique_days = set()
        unique_times = set()

        for index, row in df.iterrows():
            day = str(row['Day']).strip()
            start_time = str(row['Start Time']).strip()
            end_time = str(row['End Time']).strip()
            subject = str(row['Subject']).strip()
            time_slot = f"{start_time} - {end_time}"
            class_id = f"{day}_{start_time.replace(':', '')}-{end_time.replace(':', '')}_{subject.replace(' ', '')}"
            
            if day not in timetable_grid:
                timetable_grid[day] = {}
            
            timetable_grid[day][time_slot] = {"Subject": subject, "id": class_id}
            unique_days.add(day)
            unique_times.add(time_slot)

        sorted_days = sorted(list(unique_days), key=get_day_order)
        sorted_times = sorted(list(unique_times), key=lambda x: x.split(' - ')[0])

        user_id = ObjectId(current_user.id)
        timetables_collection.delete_many({"user_id": user_id})

        timetables_collection.insert_one({
            "user_id": user_id,
            "grid": timetable_grid,
            "days": sorted_days,
            "times": sorted_times,
            "html_table": df.to_html(classes='table table-bordered table-striped')
        })
        
        flash('Timetable uploaded and stored successfully!', 'success')
        return redirect(url_for('mark_attendance_today'))

    except Exception as e:
        print(f"AN ERROR OCCURRED IN UPLOAD: {e}") 
        flash(f'Error processing file: {e}', 'error')
        return redirect(url_for('index'))
    
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_id = ObjectId(current_user.id)
    
    if request.method == 'POST':
        min_percent = request.form.get('min_percentage')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')

        settings_collection.update_one(
            {'user_id': user_id},
            {'$set': {
                'min_attendance_percentage': float(min_percent),
                'semester_start_date': start_date,
                'semester_end_date': end_date,
                'user_id': user_id 
            }},
            upsert=True
        )
        flash('Settings saved successfully!', 'success')
        return redirect(url_for('settings'))

    
    user_settings = settings_collection.find_one({'user_id': user_id})
    if not user_settings:
        user_settings = {} 

    return render_template('settings.html', settings=user_settings)


@app.route('/attendance_summary')
@login_required 
def attendance_summary():
    user_id = ObjectId(current_user.id)
    
    pipeline = [
        {
            "$match": {"user_id": user_id}
        },
        {
            "$group": {
                "_id": "$subject",
                "present": {
                    "$sum": {
                        "$cond": [{"$eq": ["$status", "Present"]}, 1, 0]
                    }
                },
                "total": {"$sum": 1}
            }
        },
        {
            "$project": {
                "_id": 0,
                "subject": "$_id",
                "present": "$present",
                "total": "$total",
                "percentage": {
                    "$cond": { 
                        "if": {"$eq": ["$total", 0]},
                        "then": 0,
                        "else": {"$multiply": [{"$divide": ["$present", "$total"]}, 100]}
                    }
                }
            }
        },
        {"$sort": {"subject": 1}}
    ]

    summary_list = list(attendance_log_collection.aggregate(pipeline))

    formatted_summary = {
        item['subject']: {
            'present': item['present'],
            'total': item['total'],
            'percentage': f"{item['percentage']:.2f}"
        } for item in summary_list
    }

    return render_template('attendance_summary.html', summary=formatted_summary)


@app.route('/view_current_timetable')
@login_required
def view_current_timetable():
    timetable = timetables_collection.find_one({"user_id": ObjectId(current_user.id)})
    
    if timetable and 'html_table' in timetable:
        return render_template('timetable_view.html', table_html=timetable['html_table'])
    else:
        flash('No timetable has been uploaded yet.', 'info')
        return redirect(url_for('index'))
    
    
@app.route('/mark_attendance')
@login_required
def mark_attendance_today():
    today_str = datetime.now().strftime('%Y-%m-%d')
    return redirect(url_for('mark_attendance_for_date', date_str=today_str))

@app.route('/mark_attendance/<date_str>', methods=['GET', 'POST'])
@login_required
def mark_attendance_for_date(date_str):
    user_id = ObjectId(current_user.id)
    
    try:
        selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        flash("Invalid date format.", "danger")
        return redirect(url_for('mark_attendance_today'))

    today = date.today()
    
    if selected_date > today:
        flash("You cannot mark attendance for a future date.", "warning")
        return redirect(url_for('mark_attendance_today'))
        
    user_settings = settings_collection.find_one({"user_id": user_id})
    if user_settings and 'semester_start_date' in user_settings:
        start_date = datetime.strptime(user_settings['semester_start_date'], '%Y-%m-%d').date()
        if selected_date < start_date:
            flash("You cannot mark attendance for a date before your semester began.", "warning")
            return redirect(url_for('mark_attendance_today'))

    timetable_data = timetables_collection.find_one({"user_id": user_id})

    if not timetable_data:
        flash('No timetable found. Please upload one first.', 'info')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        for class_id_from_form, status in request.form.items():
            if class_id_from_form.startswith('status_'):
                class_id = class_id_from_form.replace('status_', '')
                
                attendance_log_collection.update_one(
                    {"class_id": class_id, "date": date_str, "user_id": user_id},
                    {"$set": {
                        "status": status,
                        "subject": class_id.split('_')[-1],
                        "user_id": user_id
                    }},
                    upsert=True
                )
        flash(f'Attendance for {date_str} has been saved!', 'success')
        return redirect(url_for('mark_attendance_for_date', date_str=date_str))

    day_attendance_cursor = attendance_log_collection.find({"user_id": user_id, "date": date_str})
    day_attendance = {item['class_id']: item['status'] for item in day_attendance_cursor}

    return render_template('mark_attendance.html',
                           timetable_grid=timetable_data['grid'],
                           all_days=timetable_data['days'],
                           all_times=timetable_data['times'],
                           day_attendance=day_attendance,
                           selected_date=date_str)


def get_semester_holidays():
    if 'credentials' not in session:
        return None 

    user_settings = settings_collection.find_one({"user_id": ObjectId(current_user.id)})
    if not user_settings:
        return [] 
    
    credentials = google.oauth2.credentials.Credentials(
        **session['credentials']
    )
    
    service = build('calendar', 'v3', credentials=credentials)
    
    start_date = user_settings['semester_start_date'] + "T00:00:00Z"
    end_date = user_settings['semester_end_date'] + "T23:59:59Z"
    
    calendar_id = 'en.indian#holiday@group.v.calendar.google.com'
    
    events_result = service.events().list(
        calendarId=calendar_id,
        timeMin=start_date,
        timeMax=end_date,
        singleEvents=True,
        orderBy='startTime'
    ).execute()
    
    holidays = [event['start']['date'] for event in events_result.get('items', [])]
    return holidays

def calculate_net_scheduled_classes(subject_name, timetable, start_date, end_date, holidays):
    """Calculates the total number of classes for a subject in a date range, excluding holidays."""
    
    subject_schedule = []
    if 'grid' in timetable:
        for day, day_data in timetable['grid'].items():
            for class_info in day_data.values():
                if class_info['Subject'] == subject_name:
                    subject_schedule.append(day)

    total_classes = 0
    current_date = start_date
    while current_date <= end_date:
        if current_date.strftime('%A') in subject_schedule:
            if current_date.strftime('%Y-%m-%d') not in holidays:
                total_classes += 1
        current_date += timedelta(days=1)
        
    return total_classes

@app.route('/predict_bunk/<subject_name>')
@login_required
def predict_bunk(subject_name):
    user_id = ObjectId(current_user.id)
    
    settings = settings_collection.find_one({"user_id": user_id})
    if not settings:
        return {"error": "Settings not found. Please configure them first."}, 404

    min_percent = settings['min_attendance_percentage']
    start_date = datetime.strptime(settings['semester_start_date'], '%Y-%m-%d')
    end_date = datetime.strptime(settings['semester_end_date'], '%Y-%m-%d')

    timetable = timetables_collection.find_one({"user_id": user_id})
    if not timetable:
        return {"error": "Timetable not found. Please upload one first."}, 404
        
    holidays = get_semester_holidays()
    if holidays is None:
        return {"error": "Google Calendar not authenticated."}, 401

    net_total_classes = calculate_net_scheduled_classes(subject_name, timetable, start_date, end_date, holidays)
    if net_total_classes == 0:
       return {"error": f"No classes found for subject '{subject_name}' in this semester."}, 404
    
    logs = list(attendance_log_collection.find({"subject": subject_name, "user_id": user_id}))
    classes_attended = len([log for log in logs if log['status'] == 'Present'])
    classes_held_so_far = len(logs)
    current_bunks = classes_held_so_far - classes_attended
    
    max_allowed_bunks = math.floor(net_total_classes * (1 - (min_percent / 100)))

    is_safe = current_bunks < max_allowed_bunks
    bunks_remaining = max_allowed_bunks - current_bunks - 1 if is_safe else 0

    # --- NEW LOGIC TO CHECK FOR EVENTS ---
    today_str = datetime.now().strftime('%Y-%m-%d')
    important_event = events_collection.find_one({
        "user_id": user_id,
        "subject": subject_name,
        "event_date": today_str
    })
    
    event_warning = None
    if important_event:
        # If an event is found, create a warning message and override the safety check
        event_warning = f"Warning: You have a '{important_event['event_type']}' scheduled today!"
        is_safe = False

    return {
       "subject": subject_name,
       "is_safe_to_bunk": is_safe,
       "event_warning": event_warning, # Pass the warning to the frontend
       "bunks_remaining_after_this": bunks_remaining,
       "current_attendance_stats": {
            "attended": classes_attended,
            "held_so_far": classes_held_so_far,
            "current_bunks": current_bunks,
            "max_allowed_bunks": max_allowed_bunks
       },
       "semester_stats": {
            "total_net_classes": net_total_classes,
            "min_percentage_req": min_percent
       }
    }

@app.route('/events', methods=['GET', 'POST'])
@login_required
def events():
    user_id = ObjectId(current_user.id)

    if request.method == 'POST':
        
        events_collection.insert_one({
            "user_id": user_id,
            "subject": request.form.get('subject'),
            "event_type": request.form.get('event_type'),
            "event_date": request.form.get('event_date'),
            "notes": request.form.get('notes')
        })
        flash('Event added successfully!', 'success')
        return redirect(url_for('events'))

   
    timetable_data = timetables_collection.find_one({"user_id": user_id})
    subjects = []
    if timetable_data and 'grid' in timetable_data:
       
        all_subjects = set()
        for day in timetable_data['grid'].values():
            for class_info in day.values():
                all_subjects.add(class_info['Subject'])
        subjects = sorted(list(all_subjects))

    upcoming_events = list(events_collection.find({"user_id": user_id}).sort("event_date", 1))
    
    return render_template('events.html', events=upcoming_events, subjects=subjects)

if __name__ == '__main__':
    app.run(debug=True)