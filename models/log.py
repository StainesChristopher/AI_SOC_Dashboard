from app import db

class SecurityLog(db.Model):

    __tablename__ = "security_logs"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    event_type = db.Column(db.String(100))
    status = db.Column(db.String(20))
    event_time = db.Column(db.DateTime)