from datetime import datetime
from flask import Flask, render_template, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors

app = Flask(__name__)

app.config['SECRET_KEY'] = 'soc_dashboard_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/soc_dashboard'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# -----------------------------
# User Model
# -----------------------------
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="Analyst")

class SecurityLog(db.Model):
    __tablename__ = "security_logs"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    ip_address = db.Column(db.String(50))
    event_type = db.Column(db.String(50))
    status = db.Column(db.String(20))
    event_time = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    ip_address = db.Column(db.String(50))
    status = db.Column(db.String(20))
    description = db.Column(db.Text)
    alert_time = db.Column(db.DateTime, default=datetime.utcnow)

# -----------------------------
# Home
# -----------------------------
@app.route("/")
def home():
    return redirect("/login")

# -----------------------------
# Register
# -----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash("Username already exists!")
            return redirect("/register")

        user = User(
            username=username,
            email=email,
            password=password,
            role="Analyst"
        )

        db.session.add(user)
        db.session.commit()

        flash("Registration Successful!")
        return redirect("/login")

    return render_template("register.html")

# -----------------------------
# Login
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        print("Username entered:", username)
        print("Password entered:", password)
        print("User found:", user)
        if user:
            print("Stored hash:", user.password)
            print("Password matches:", check_password_hash(user.password, password))

        if user and check_password_hash(user.password, password):
            session["user"] = user.username
            session["role"] = user.role
            
            log = SecurityLog(
                username=username,
                ip_address=request.remote_addr,
                event_type="Login",
                status="Success"
            )
            
            db.session.add(log)
            try:
                db.session.commit()
                print("SUCCESS LOG SAVED")
            except Exception as e:
                db.session.rollback()
                print(e)
            return redirect("/dashboard")

            
        log = SecurityLog(
            username=username,
            ip_address=request.remote_addr,
            event_type="Login",
            status="Failed"
        )
        db.session.add(log)
        db.session.commit()
        failed_attempts = SecurityLog.query.filter_by(
            ip_address=request.remote_addr,
            status="Failed"
        ).count()
        print("Failed Attempts:", failed_attempts)
        print("Reached Alert Check")
        if failed_attempts >= 5:
            print("Failed Attempts =", failed_attempts)
            existing_alert = Alert.query.filter_by(
                ip_address=request.remote_addr,
                threat_type="Brute Force Attack"
            ).first()
            if not existing_alert:
                alert = Alert(
                    threat_type="Brute Force Attack",
                    severity="High",
                    ip_address=request.remote_addr,
                    status="Open",
                    description=f"Detected {failed_attempts} failed login attempts from {request.remote_addr}"
                )
                try:
                    db.session.add(alert)
                    db.session.commit()
                    print("✅ ALERT CREATED")
                except Exception:
                    db.session.rollback()
                    import traceback
                    traceback.print_exc()
                
        flash("Invalid Username or Password")

    return render_template("login.html")

# -----------------------------
# Dashboard
# -----------------------------
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    total_users = User.query.count()

    total_logs = SecurityLog.query.count()

    total_alerts = Alert.query.count()

    failed_logins = SecurityLog.query.filter_by(status="Failed").count()
    if failed_logins < 5:
        threat_level = "🟢 Low"
    elif failed_logins < 15:
        threat_level = "🟡 Medium"
    else:
        threat_level = "🔴 High"
    success_logins = SecurityLog.query.filter_by(status="Success").count()
    open_alerts = Alert.query.filter_by(status="Open").count()
    resolved_alerts = Alert.query.filter_by(status="Resolved").count()
    recent_logs = SecurityLog.query.order_by(SecurityLog.event_time.desc()).limit(5).all()
    current_time = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")
    return render_template(
        "dashboard.html",
         username=session["user"],
         total_users=total_users,
         total_logs=total_logs,
         total_alerts=total_alerts,
         failed_logins=failed_logins,
         success_logins=success_logins,
         recent_logs=recent_logs,
         open_alerts=open_alerts,
         resolved_alerts=resolved_alerts,
         threat_level=threat_level,
         current_time=current_time
    )

# -----------------------------
# Alerts Page
# -----------------------------

@app.route("/resolve_alert/<int:id>")
def resolve_alert(id):

    alert = Alert.query.get_or_404(id)

    alert.status = "Resolved"

    db.session.commit()

    flash("Alert Resolved Successfully!")

    return redirect("/alerts")

@app.route("/alerts")
def alerts():

    if "user" not in session:
        return redirect("/login")

    all_alerts = Alert.query.order_by(Alert.id.desc()).all()

    return render_template(
        "alerts.html",
        alerts=all_alerts
    )

# -----------------------------
# Logout
# -----------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# -----------------------------
# Create Tables
# -----------------------------
with app.app_context():
    db.create_all()

# -----------------------------
# Run
# -----------------------------
from flask import send_file
import os

@app.route("/export_pdf")
def export_pdf():

    logs = SecurityLog.query.order_by(SecurityLog.event_time.desc()).all()

    pdf_file = "security_logs_report.pdf"

    doc = SimpleDocTemplate(pdf_file)

    data = [["Username", "IP Address", "Event", "Status", "Time"]]

    for log in logs:
        data.append([
            log.username,
            log.ip_address,
            log.event_type,
            log.status,
            str(log.event_time)
        ])

    table = Table(data)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.grey),
        ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
        ("GRID", (0,0), (-1,-1), 1, colors.black),
        ("BACKGROUND", (0,1), (-1,-1), colors.beige),
        ("FONTSIZE", (0,0), (-1,-1), 9)
    ]))

    doc.build([table])

    return send_file(pdf_file, as_attachment=True)
@app.route("/logs")
def logs():

    search = request.args.get("search", "")

    if search:
        logs = SecurityLog.query.filter(
            SecurityLog.username.like(f"%{search}%")
        ).order_by(SecurityLog.event_time.desc()).all()
    else:
        logs = SecurityLog.query.order_by(
            SecurityLog.event_time.desc()
        ).all()

    return render_template(
        "logs.html",
        logs=logs,
        search=search
    )

@app.route("/generate_alert")
def generate_alert():

    alert = Alert(
        threat_type="Manual Alert",
        severity="Medium",
        ip_address="127.0.0.1",
        status="Open",
        description="Alert generated manually by administrator."
    )

    db.session.add(alert)
    db.session.commit()

    flash("Alert Generated Successfully!")

    return redirect("/alerts")

@app.route("/clear_logs")
def clear_logs():

    SecurityLog.query.delete()
    db.session.commit()

    flash("All Security Logs Cleared!")

    return redirect("/logs")

@app.route("/clear_alerts")
def clear_alerts():

    Alert.query.delete()
    db.session.commit()

    flash("All Alerts Cleared!")

    return redirect("/alerts")

if __name__ == "__main__":
    app.run(debug=True)
