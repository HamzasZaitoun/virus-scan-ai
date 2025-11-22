from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Scan(db.Model):
    """Scan results model"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    target_type = db.Column(db.String(10), nullable=False, index=True)
    target_value = db.Column(db.Text, nullable=False)
    label = db.Column(db.String(20), nullable=False, index=True)
    risk_score = db.Column(db.Integer, nullable=False, index=True)
    reasons = db.Column(db.JSON, nullable=False)
    solutions = db.Column(db.JSON, nullable=False)
    client_ip = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f'<Scan {self.id}: {self.target_value[:50]}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'target_type': self.target_type,
            'target_value': self.target_value,
            'label': self.label,
            'risk_score': self.risk_score,
            'reasons': self.reasons,
            'solutions': self.solutions,
            'created_at': self.created_at.isoformat()
        }

class User(db.Model):
    """User model for future authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<User {self.email}>'

class Feedback(db.Model):
    """User feedback model"""
    __tablename__ = 'feedback'
    
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(255))
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Feedback {self.id}: {self.rating} stars>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'rating': self.rating,
            'comment': self.comment,
            'created_at': self.created_at.isoformat()
        }

class ContactMessage(db.Model):
    """Contact form submissions"""
    __tablename__ = 'contact_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='unread')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ContactMessage {self.id}: {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'message': self.message,
            'status': self.status,
            'created_at': self.created_at.isoformat()
        }