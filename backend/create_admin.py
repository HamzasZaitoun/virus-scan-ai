#!/usr/bin/env python3
"""
Create an admin user for ViruScan AI
Run this script to create your first admin account
"""

import os
from werkzeug.security import generate_password_hash
from app import app, db
from models import User

def create_admin():
    """Create admin user"""
    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(email='admin@viruscan.com').first()
        
        if admin:
            print("⚠️  Admin user already exists!")
            print(f"   Email: admin@viruscan.com")
            return
        
        # Create admin user
        admin = User(
            email='admin@viruscan.com',
            full_name='Admin User',
            phone='+962 7 XXX XXXX',
            password_hash=generate_password_hash('admin123'),
            is_admin=True
        )
        
        db.session.add(admin)
        db.session.commit()
        
        print("✅ Admin user created successfully!")
        print("=" * 50)
        print("Email:    admin@viruscan.com")
        print("Password: admin123")
        print("=" * 50)
        print("⚠️  IMPORTANT: Change this password after first login!")

if __name__ == "__main__":
    create_admin()