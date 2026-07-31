# app.py — improved version for BunkWise
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
from datetime import datetime, date, timedelta
import fitz  # PyMuPDF
import re
import time as time_module

app = Flask(__name__)
app.secret_key = 'asdfghjkl'  # consider using env var for production

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']

# --- Database setup (keep your connection string secure in env var for prod) ---
client = MongoClient("mongodb+srv://10caditiverma:ZGzxoFRG8YEEpfz4@cluster1.jvmwija.mongodb.net/?retryWrites=true&w=majority&appName=Cluster1")
db = client['attendance_app_db']
users_collection = db['users']
timetables_collection = db['timetables']
settings_collection = db['settings']
attendance_log_collection = db['attendance_log']
events_collection = db['events']

# --- Login manager ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data.get("username", "")

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = users_collection.find_one({"_id": ObjectId(user_id)})
        return User(user_data) if user_data else None
    except Exception:
        return None

# --- Helpers ---
def get_day_order(day_name):
    order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    try:
        return order.index(day_name)
    except ValueError:
        return len(order)

def sanitize_subject(subject):
    # remove unwanted characters for IDs
    return re.sub(r'[^A-Za-z0-9]', '', subject)

def normalize_time_str(t_str):
    """
    Try to normalize a time string to HH:MM (24-hour). Returns normalized string or original stripped string.
    Supports formats like: "09:00", "9:00", "9:00 AM", "09.00", "9-00", "0900".
    """
    if not isinstance(t_str, str):
        t_str = str(t_str)
    s = t_str.strip()
    if not s:
        return s
    s = s.replace('.', ':').replace('-', ':')
    s = re.sub(r'\s+', ' ', s)

    # Try common patterns
    patterns = [
        '%H:%M',
        '%I:%M %p',
        '%I:%M%p',
        '%H%M',
        '%I %p',
        '%I:%M %P'  # fallback - harmless
    ]

    for p in patterns:
        try:
            dt = datetime.strptime(s.upper(), p)
            return dt.strftime('%H:%M')
        except Exception:
            pass

    # If there's an AM/PM indicator like "9am" or "9 am"
    m = re.match(r'(\d{1,2}):?(\d{2})?\s*([AaPp][Mm])', s)
    if m:
        h = int(m.group(1))
        m2 = m.group(2) or '00'
        ampm = m.group(3).lower()
        if ampm.startswith('p') and h != 12:
            h += 12
        if ampm.startswith('a') and h == 12:
            h = 0
        return f"{h:02d}:{int(m2):02d}"

    # last-ditch: extract digits
    digits = re.findall(r'\d+', s)
    if digits:
        if len(digits[0]) <= 2:
            # treat as hour only
            h = int(digits[0])
            return f"{h:02d}:00"
        elif len(digits[0]) == 3:  # e.g. 900 -> 09:00
            s1 = digits[0].zfill(4)
            return f"{s1[:2]}:{s1[2:]}"
        elif len(digits[0]) >= 4:
            s1 = digits[0].zfill(4)
            return f"{s1[:2]}:{s1[2:4]}"

    return s  # fallback: return original-ish

def sort_time_slots(slots):
    # slots are strings like "HH:MM - HH:MM" or possibly other formats
    def key_fn(ts):
        start = ts.split(' - ')[0].strip()
        try:
            return datetime.strptime(normalize_time_str(start), '%H:%M')
        except Exception:
            return datetime.strptime('00:00', '%H:%M')
    return sorted(slots, key=key_fn)

# --- PDF parsing: try Camelot for tabular PDFs, else fallback to text-block parsing with PyMuPDF (fitz) ---
def parse_timetable_from_pdf_bytes(pdf_bytes):
    """
    Returns a DataFrame with columns ['Day', 'Start Time', 'End Time', 'Subject']
    or None if parsing failed.
    """
    # save to a temp file because camelot needs a filepath
    tmp_dir = "uploads"
    os.makedirs(tmp_dir, exist_ok=True)
    tmp_path = os.path.join(tmp_dir, f"tmp_pdf_{int(time_module.time())}.pdf")
    with open(tmp_path, 'wb') as f:
        f.write(pdf_bytes)

    # Try Camelot (lattice flavor) — good for scanned tables with lines
    try:
        tables = camelot.read_pdf(tmp_path, pages='all', flavor='lattice')
        if not tables or len(tables) == 0:
            tables = camelot.read_pdf(tmp_path, pages='all', flavor='stream')  # try stream fallback

        if tables and len(tables) > 0:
            # try to find columns that look like Day/Start/End/Subject or have day headers
            for table in tables:
                df = table.df.copy()
                # Normalize header row
                header = [str(c).strip() for c in df.iloc[0].tolist()]
                df = df[1:].copy()
                df.columns = header
                # Find columns that can map to Day/Time/Subject
                potential_mappings = {}
                cols = [c.lower() for c in df.columns]
                for c in df.columns:
                    lc = c.lower()
                    if any(k in lc for k in ['day', 'weekday', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']):
                        potential_mappings['Day'] = c
                    if any(k in lc for k in ['start', 'from', 'time']):
                        if 'Start Time' not in potential_mappings:
                            potential_mappings['Start Time'] = c
                    if any(k in lc for k in ['end', 'to']):
                        if 'End Time' not in potential_mappings:
                            potential_mappings['End Time'] = c
                    if any(k in lc for k in ['subject', 'course', 'class', 'module']):
                        potential_mappings['Subject'] = c

                # If we found at least Day and Subject and one time column, try to construct DF
                if 'Day' in potential_mappings and 'Subject' in potential_mappings and ('Start Time' in potential_mappings or 'End Time' in potential_mappings):
                    rows = []
                    for _, r in df.iterrows():
                        day = str(r[potential_mappings['Day']]).strip()
                        start = str(r[potential_mappings.get('Start Time', '')]).strip() if potential_mappings.get('Start Time') else ''
                        end = str(r[potential_mappings.get('End Time', '')]).strip() if potential_mappings.get('End Time') else ''
                        subject = str(r[potential_mappings['Subject']]).strip()
                        # If times combined like "09:00-10:00" try to split
                        if (not start or not end) and '-' in start:
                            parts = start.split('-')
                            start = parts[0].strip()
                            end = parts[1].strip() if len(parts) > 1 else ''
                        rows.append([day, normalize_time_str(start), normalize_time_str(end), subject])
                    if rows:
                        return pd.DataFrame(rows, columns=['Day', 'Start Time', 'End Time', 'Subject'])
            # if Camelot found tables but could not map, continue to fallback
    except Exception as e:
        # camelot may throw errors depending on environment; fall back silently
        print(f"Camelot attempt failed: {e}")

    # --- Fallback: use PyMuPDF text blocks and simple layout heuristics ---
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        page = doc[0]  # assume first page contains timetable
        blocks = page.get_text("blocks")  # list of tuples (x0, y0, x1, y1, "text", ...)
        # Normalize block text and find header row
        # Look for a header line that contains day names (full or short)
        days_keywords = ['mon', 'monday', 'tue', 'tues', 'tuesday', 'wed', 'wednesday', 'thu', 'thurs', 'thursday',
                         'fri', 'friday', 'sat', 'saturday', 'sun', 'sunday']
        header_y = None
        for b in blocks:
            txt = str(b[4]).lower()
            if any(k in txt for k in days_keywords):
                header_y = b[1]
                break
        if header_y is None:
            # no header found — try to parse rows that look like "DAY | 09:00 - 10:00 | Subject"
            rows = []
            for b in sorted(blocks, key=lambda x: (x[1], x[0])):
                txt = b[4].strip()
                lines = [ln.strip() for ln in txt.split('\n') if ln.strip()]
                for ln in lines:
                    # pattern like "MON 09:00-10:00 Subject"
                    m = re.match(r'^(?P<day>[A-Za-z]{3,9})\s+(.+)$', ln)
                    if m:
                        rest = ln[m.end():].strip()
                        # attempt to find times
                        time_match = re.search(r'(\d{1,2}[:.]\d{2}\s*(?:AM|PM|am|pm)?)\s*[-–]\s*(\d{1,2}[:.]\d{2}\s*(?:AM|PM|am|pm)?)', ln)
                        if time_match:
                            start = normalize_time_str(time_match.group(1))
                            end = normalize_time_str(time_match.group(2))
                            subj = re.sub(r'^\w+\s*', '', ln).strip()
                            rows.append([m.group('day'), start, end, subj])
            if rows:
                return pd.DataFrame(rows, columns=['Day', 'Start Time', 'End Time', 'Subject'])
            # else fail
            return None

        header_blocks = [b for b in blocks if abs(b[1] - header_y) < 12]
        header_blocks = sorted(header_blocks, key=lambda b: b[0])
        # map column center x -> day name
        days_map = {
            'mon': 'Monday', 'monday': 'Monday',
            'tue': 'Tuesday', 'tues': 'Tuesday', 'tuesday': 'Tuesday',
            'wed': 'Wednesday', 'wednesday': 'Wednesday',
            'thu': 'Thursday', 'thurs': 'Thursday', 'thursday': 'Thursday',
            'fri': 'Friday', 'friday': 'Friday',
            'sat': 'Saturday', 'saturday': 'Saturday',
            'sun': 'Sunday', 'sunday': 'Sunday'
        }
        col_centers = {}
        for hb in header_blocks:
            center_x = (hb[0] + hb[2]) / 2.0
            txt = hb[4].strip().lower()
            for k, v in days_map.items():
                if k in txt:
                    col_centers[center_x] = v
                    break

        if not col_centers:
            return None

        sorted_centers = sorted(col_centers.keys())
        timetable_rows = []
        # content blocks below header
        content_blocks = [b for b in blocks if b[1] > header_y + 2]
        for cb in content_blocks:
            txt = cb[4].strip()
            if not txt:
                continue
            center_x = (cb[0] + cb[2]) / 2.0
            # find nearest column center
            nearest = min(sorted_centers, key=lambda c: abs(c - center_x))
            day = col_centers[nearest]
            lines = [ln.strip() for ln in txt.split('\n') if ln.strip()]
            # lines often: "09:00 - 10:00\nSubject Name"
            if lines:
                # if first line contains a time range
                first = lines[0]
                time_match = re.search(r'(\d{1,2}[:.]\d{2}\s*(?:AM|PM|am|pm)?)\s*[-–]\s*(\d{1,2}[:.]\d{2}\s*(?:AM|PM|am|pm)?)', first)
                if time_match:
                    start = normalize_time_str(time_match.group(1))
                    end = normalize_time_str(time_match.group(2))
                    subject = lines[1] if len(lines) > 1 else 'Unknown'
                    timetable_rows.append([day, start, end, subject])
                else:
                    # sometimes single-line "09:00-10:00 Subject"
                    tm = re.search(r'(\d{1,2}[:.]\d{2}\s*(?:AM|PM|am|pm)?)\s*[-–]\s*(\d{1,2}[:.]\d{2}\s*(?:AM|PM|am|pm)?)\s*(.*)', txt)
                    if tm:
                        start = normalize_time_str(tm.group(1))
                        end = normalize_time_str(tm.group(2))
                        subject = tm.group(3).strip() or 'Unknown'
                        timetable_rows.append([day, start, end, subject])
                    else:
                        # Can't parse times — skip
                        continue

        if timetable_rows:
            return pd.DataFrame(timetable_rows, columns=['Day', 'Start Time', 'End Time', 'Subject'])
    except Exception as e:
        print(f"PDF fallback parse failed: {e}")
        return None

    return None

# --- Routes (only edited/cleaned duplicates and upload logic) ---
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
            filepath = os.path.join("uploads", "temp_debug.pdf")
            file.save(filepath)

            tables = []
            try:
                tables = camelot.read_pdf(filepath, pages='all', flavor='lattice')
                if not tables or len(tables) == 0:
                    tables = camelot.read_pdf(filepath, pages='all', flavor='stream')
            except Exception as ce:
                print(f"Camelot debug error: {ce}")

            if not tables or len(tables) == 0:
                flash("Camelot could not find any tables in this PDF.", "warning")
                return redirect(url_for('debug_pdf'))

            # show first table
            df = tables[0].df
            print("--- CAMELOT DEBUG OUTPUT ---")
            print(df.head())
            print("--------------------------")
            # attempt to save a grid plot (may or may not work depending on environment)
            try:
                plot_path = os.path.join("static", "debug_plot.png")
                os.makedirs("static", exist_ok=True)
                camelot.plot(tables[0], kind='grid').savefig(plot_path)
                return render_template('debug_plot.html', plot_url=url_for('static', filename='debug_plot.png', t=int(time_module.time())))
            except Exception as plot_error:
                print(f"PLOTTING FAILED: {plot_error}")
                flash(f"Table found but plotting failed: {plot_error}", "warning")
                return redirect(url_for('debug_pdf'))

        except Exception as e:
            flash(f"Unexpected error: {e}", "danger")
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
    state = session.get('state')
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
    session.pop('credentials', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


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

@app.route('/upload_timetable', methods=['GET', 'POST'])
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
            # read CSV from file stream
            try:
                # If the file is small, read directly
                df = pd.read_csv(file)
            except Exception as e:
                # fallback: read bytes then decode
                file.stream.seek(0)
                content = file.read()
                df = pd.read_csv(io.BytesIO(content))
        elif filename.lower().endswith('.pdf'):
            # read bytes and parse
            file.stream.seek(0)
            pdf_bytes = file.read()
            df = parse_timetable_from_pdf_bytes(pdf_bytes)
            if df is None:
                flash('Could not parse a timetable from the PDF. Try a CSV or ensure the PDF has a clear table or time/subject layout.', 'error')
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
            raw_day = str(row['Day']).strip()
            day = normalize_day_name(raw_day)
            if day is None:
                 continue
            start_time = normalize_time_str(str(row['Start Time']).strip())
            end_time = normalize_time_str(str(row['End Time']).strip())
            subject = str(row['Subject']).strip()
            time_slot = f"{start_time} - {end_time}"
            class_id = f"{day}_{start_time.replace(':', '')}-{end_time.replace(':', '')}_{sanitize_subject(subject)}"

            if day not in timetable_grid:
                timetable_grid[day] = {}

            timetable_grid[day][time_slot] = {"Subject": subject, "id": class_id}
            unique_days.add(day)
            unique_times.add(time_slot)

        sorted_days = sorted(list(unique_days), key=get_day_order)
        sorted_times = sort_time_slots(list(unique_times))

        user_id = ObjectId(current_user.id)
        timetables_collection.delete_many({"user_id": user_id})

        timetables_collection.insert_one({
            "user_id": user_id,
            "grid": timetable_grid,
            "days": sorted_days,
            "times": sorted_times,
            "html_table": df.to_html(classes='table table-bordered table-striped'),
            "uploaded_at": datetime.utcnow(),
            "filename": filename
        })

        flash('Timetable uploaded and stored successfully!', 'success')
        return redirect(url_for('mark_attendance_today'))

    except Exception as e:
        print(f"AN ERROR OCCURRED IN UPLOAD: {e}")
        flash(f'Error processing file: {e}', 'error')
        return redirect(url_for('index'))


# --- (rest of your routes remain mostly unchanged) ---
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

    user_settings = settings_collection.find_one({'user_id': user_id}) or {}
    return render_template('settings.html', settings=user_settings)


@app.route('/attendance_summary')
@login_required
def attendance_summary():
    user_id = ObjectId(current_user.id)
    pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {
            "_id": "$subject",
            "present": {"$sum": {"$cond": [{"$eq": ["$status", "Present"]}, 1, 0]}},
            "total": {"$sum": 1}
        }},
        {"$project": {
            "_id": 0,
            "subject": "$_id",
            "present": "$present",
            "total": "$total",
            "percentage": {"$cond": {"if": {"$eq": ["$total", 0]}, "then": 0, "else": {"$multiply": [{"$divide": ["$present", "$total"]}, 100]}}}
        }},
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
    credentials = google.oauth2.credentials.Credentials(**session['credentials'])
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
    bunks_remaining = max_allowed_bunks - current_bunks
    if bunks_remaining < 0:
        bunks_remaining = 0

    # check events for today
    today_str = datetime.now().strftime('%Y-%m-%d')
    important_event = events_collection.find_one({
        "user_id": user_id,
        "subject": subject_name,
        "event_date": today_str
    })

    event_warning = None
    if important_event:
        event_warning = f"Warning: You have a '{important_event['event_type']}' scheduled today!"
        is_safe = False

    return {
        "subject": subject_name,
        "is_safe_to_bunk": is_safe,
        "event_warning": event_warning,
        "bunks_remaining": bunks_remaining,
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
