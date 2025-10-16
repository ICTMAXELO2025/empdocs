import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import bcrypt
import io
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-this')

# Database configuration - Fixed for PostgreSQL and Render
def get_database_url():
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Fix for Render PostgreSQL URL format
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        return database_url
    else:
        # Local development - use your PostgreSQL credentials
        return 'postgresql://postgres:Maxelo@2023@localhost:5432/employee_docs'

app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True
}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure upload settings
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'}

# Models
class Employee(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    documents = db.relationship('Document', backref='owner', lazy=True, cascade='all, delete-orphan')

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return Employee.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    """Initialize database and create tables"""
    with app.app_context():
        try:
            db.create_all()
            logger.info("✅ Database tables created successfully")
            
            # Create default admin user if no users exist
            if not Employee.query.first():
                admin = Employee(
                    password_hash=generate_password_hash('admin123')
                )
                db.session.add(admin)
                db.session.commit()
                logger.info("✅ Default admin user created")
                
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")
            # Don't crash the app if database fails
            pass

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([password, confirm_password]):
            flash('All fields are required')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html')
        
        try:
            employee = Employee(
                password_hash=generate_password_hash(password)
            )
            
            db.session.add(employee)
            db.session.commit()
            
            logger.info("✅ New employee registered")
            flash('Registration successful! Please login with your credentials.')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"❌ Registration error: {e}")
            flash('Registration failed. Please try again.')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        # Since we don't have usernames, we'll use the first employee
        # In a real app, you'd want a better authentication system
        employee = Employee.query.first()
        
        if employee and check_password_hash(employee.password_hash, request.form.get('password')):
            login_user(employee)
            logger.info("✅ Employee logged in successfully")
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid password')
            logger.warning("❌ Failed login attempt")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        doc_count = Document.query.filter_by(employee_id=current_user.id).count()
    except Exception as e:
        logger.error(f"❌ Error getting document count: {e}")
        doc_count = 0
    return render_template('dashboard.html', doc_count=doc_count)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_data = file.read()
            
            if len(file_data) > app.config['MAX_CONTENT_LENGTH']:
                flash('File too large. Maximum size is 16MB.')
                return redirect(request.url)
                
            file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'unknown'
            
            try:
                document = Document(
                    filename=f"{current_user.id}_{datetime.utcnow().timestamp()}_{filename}",
                    original_filename=filename,
                    file_data=file_data,
                    employee_id=current_user.id,
                    file_size=len(file_data),
                    file_type=file_extension
                )
                
                db.session.add(document)
                db.session.commit()
                
                logger.info(f"✅ Employee uploaded file: {filename}")
                flash('File uploaded successfully!')
                return redirect(url_for('documents'))
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"❌ Upload error: {e}")
                flash('Upload failed. Please try again.')
        else:
            flash('File type not allowed. Allowed types: ' + ', '.join(ALLOWED_EXTENSIONS))
    
    return render_template('upload.html', allowed_extensions=ALLOWED_EXTENSIONS)

@app.route('/documents')
@login_required
def documents():
    try:
        employee_documents = Document.query.filter_by(employee_id=current_user.id).order_by(Document.upload_date.desc()).all()
    except Exception as e:
        logger.error(f"❌ Error getting documents: {e}")
        employee_documents = []
        flash('Error loading documents. Please try again.')
    
    return render_template('documents.html', documents=employee_documents)

@app.route('/download_document', methods=['POST'])
@login_required
def download_document():
    document_id = request.form.get('document_id')
    
    try:
        document = Document.query.get_or_404(document_id)
        
        if document.employee_id != current_user.id:
            flash('Access denied')
            logger.warning(f"❌ Unauthorized download attempt")
            return redirect(url_for('documents'))
        
        logger.info(f"✅ Employee downloaded: {document.original_filename}")
        return send_file(
            io.BytesIO(document.file_data),
            as_attachment=True,
            download_name=document.original_filename,
            mimetype='application/octet-stream'
        )
            
    except Exception as e:
        logger.error(f"❌ Download error: {e}")
        flash('Download failed. Please try again.')
    
    return redirect(url_for('documents'))

@app.route('/delete_document', methods=['POST'])
@login_required
def delete_document():
    document_id = request.form.get('document_id')
    
    try:
        document = Document.query.get_or_404(document_id)
        
        if document.employee_id != current_user.id:
            flash('Access denied')
            logger.warning(f"❌ Unauthorized delete attempt")
            return redirect(url_for('documents'))
        
        db.session.delete(document)
        db.session.commit()
        logger.info(f"✅ Employee deleted: {document.original_filename}")
        flash('File deleted successfully!')
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Delete error: {e}")
        flash('Delete failed. Please try again.')
    
    return redirect(url_for('documents'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# Error handlers
@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum size is 16MB.')
    return redirect(url_for('upload'))

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return render_template('500.html'), 500

# Initialize database when app starts
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)