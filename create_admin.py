from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Create all database tables
    db.create_all()
    
    # Check if admin exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Create new admin user
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully!")
    else:
        # Reset admin password
        admin.password_hash = generate_password_hash('admin123')
        db.session.commit()
        print("Admin password reset successfully!") 