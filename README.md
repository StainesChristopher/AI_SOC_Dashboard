# AI_SOC_Dashboard
AI-powered Security Operations Center Dashboard using Flask and MySQL.

#  AI SOC Dashboard

An AI-powered Security Operations Center (SOC) Dashboard built using Flask, MySQL, Bootstrap, and Chart.js. This project monitors login activities, detects brute-force attacks, generates security alerts, and provides an interactive dashboard for security analysis.

##  Features

- User Registration & Secure Login
-  Password Hashing
-  Session Management
-  Dashboard with Security Statistics
-  Security Log Monitoring
-  Search Security Logs
-  Automatic Brute Force Attack Detection
-  Automatic Alert Generation
-  Resolve Security Alerts
-  Login Statistics Chart
-  Alert Statistics Chart
-  AI Threat Level Indicator
-  Export Security Logs to PDF
-  Dashboard Date & Time
-  Clear Logs & Alerts

##  Technologies Used

- Python 3.x
- Flask
- Flask-SQLAlchemy
- MySQL
- Bootstrap 5
- Chart.js
- ReportLab
- HTML5
- CSS3
- JavaScript

## Project Structure

AI_SOC_Dashboard/
│
├── app.py
├── requirements.txt
├── README.md
│
├── templates/
│   ├── dashboard.html
│   ├── login.html
│   ├── register.html
│   ├── logs.html
│   └── alerts.html
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
└── security_logs_report.pdf




## Installation

Clone the repository

bash
git clone https://github.com/yourusername/AI_SOC_Dashboard.git
cd AI_SOC_Dashboard


### Install dependencies

bash
pip install -r requirements.txt


### Configure MySQL

Create a database named:

soc_dashboard

Update your database connection in `app.py` if required.

python

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:@localhost/soc_dashboard"

### Run the project

bash

python app.py

Open your browser:

http://127.0.0.1:5000

## Dashboard Features

- Dashboard Overview
- Login Statistics
- Alert Statistics
- AI Threat Level
- Security Logs
- Alerts Management
- PDF Report Export

##  Security Features

- Password Hashing
- Brute Force Detection
- Security Event Logging
- Session Authentication
- Alert Generation
- Alert Resolution

## Future Enhancements

- Email Notifications
- Machine Learning Based Threat Detection
- Role-Based Access Control
- Real-Time Monitoring
- Multi-Factor Authentication
- Cloud Deployment

## Developed By

**Staines Christopher C**

B.E. Computer Science and Engineering (Cyber Security)

Prathyusha Engineering College


##  License

This project is developed for educational and academic purposes.
