from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from whoosh import spelling
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import logging
import shutil
from whoosh.fields import Schema, TEXT, ID
from whoosh.qparser import QueryParser
from sqlalchemy.exc import IntegrityError
from whoosh import index as whoosh_index
from collections import Counter
import re

# -------------------- App Initialization --------------------

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Used to sign session cookies

# Configure SQLite database and upload directory
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///database.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    UPLOAD_FOLDER='uploads'
)

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
whoosh_log = logging.getLogger("whoosh")
whoosh_log.setLevel(logging.WARNING)

# Ensure upload and index directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
INDEX_DIR = "indexdir"
if not os.path.exists(INDEX_DIR):
    os.makedirs(INDEX_DIR)
    schema = Schema(filename=ID(stored=True), content=TEXT)
    whoosh_index.create_in(INDEX_DIR, schema, indexname='main')


def create_admin_account():
    """
    Create an admin user from environment variables on startup if none exists.
    """
    with app.app_context():
        email = os.environ.get('ADMIN_EMAIL')
        admin = User.query.filter_by(email=email).first()
        if not admin:
            default_pw = os.environ.get('ADMIN_PASSWORD')
            if not default_pw:
                print("WARNING: ADMIN_PASSWORD not set; skipping admin creation.")
                return
            hashed = generate_password_hash(default_pw)
            new_admin = User(
                username='Admin',
                email=email,
                password=hashed,
                is_admin=True
            )
            db.session.add(new_admin)
            db.session.commit()
            print("Admin account created.")
        else:
            print("Admin account already exists.")


# -------------------- Database Models --------------------

class User(db.Model):
    """
    User accounts: regular or admin.
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'


class Document(db.Model):
    """
    Uploaded documents metadata.
    """
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<Document {self.filename}>'


class CustomDictionary(db.Model):
    """
    Stores user-specific custom spelled words.
    """
    __tablename__ = 'custom_dictionary'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    word = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<CustomDictionary {self.word}>'


# Create tables if they don't exist
with app.app_context():
    db.create_all()


# -------------------- Utility Functions --------------------

def index_document(filename, filepath):
    """
    Improved document indexing with better error handling and validation
    """
    try:
        # Check if file exists and is readable
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return False

        # Read file content with proper encoding handling
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(filepath, 'r', encoding='latin-1') as f:
                content = f.read()

        # Ensure we have content to index
        if not content.strip():
            logger.warning(f"Empty file: {filename}")
            return False

        # Create index if it doesn't exist
        if not whoosh_index.exists_in(INDEX_DIR):
            os.makedirs(INDEX_DIR, exist_ok=True)
            schema = Schema(filename=ID(stored=True), content=TEXT)
            whoosh_index.create_in(INDEX_DIR, schema)

        ix = whoosh_index.open_dir(INDEX_DIR)
        writer = ix.writer()
        
        # Check if document already exists in index
        with ix.searcher() as searcher:
            if list(searcher.document(filename=filename)):
                writer.delete_by_term('filename', filename)
                
        writer.add_document(filename=filename, content=content)
        writer.commit()
        return True
        
    except Exception as e:
        logger.error(f"Indexing error for {filename}: {str(e)}")
        return False

def get_highlighted_snippets(content, query, num_words=20):
    """
    Return up to 3 snippets containing the search query,
    highlighting any occurrences and counting total occurrences.
    """
    if not content or not query:
        return {'snippets': ["No content available"], 'occurrence_count': 0}

    words = content.split()
    query_terms = [term.lower() for term in query.split()]
    occurrence_count = sum(
        1 for w in words if any(q in w.lower() for q in query_terms)
    )

    matches = [
        i for i, w in enumerate(words)
        if any(q in w.lower() for q in query_terms)
    ]

    if not matches:
        return {'snippets': ["No matches found"], 'occurrence_count': 0}

    snippets = []
    for pos in matches[:3]:
        start = max(0, pos - num_words)
        end = min(len(words), pos + num_words)
        segment = ' '.join(words[start:end])
        # Wrap matched terms in <mark> tags
        for term in query_terms:
            segment = re.sub(
                f"({re.escape(term)})", r'<mark>\1</mark>',
                segment, flags=re.IGNORECASE
            )
        snippets.append(f"...{segment}...")

    return {'snippets': snippets, 'occurrence_count': occurrence_count}


# -------------------- Flask Routes --------------------

@app.route('/', methods=['GET', 'POST'])
def home():
    """Home page with search functionality and admin dashboard"""
    try:
        # Get search query from request
        query = request.args.get('q', '').strip()
        
        # Initialize variables
        results = []
        users = []
        documents = []
        
        # Check if user is admin
        is_admin = session.get('is_admin', False)
        print(f"Admin status: {is_admin}")
        print(f"Session data: {dict(session)}")
        
        # Get users and documents for admin users
        if is_admin:
            try:
                # Fetch all users from database
                users = User.query.all()
                print(f"Users from DB: {len(users)} users found")
                for user in users:
                    print(f"User: {user.id}, {user.username}, {user.email}, admin:{user.is_admin}")
                
                # Get document list from upload folder
                upload_folder = app.config['UPLOAD_FOLDER']
                print(f"Upload folder: {upload_folder}")
                
                if os.path.exists(upload_folder):
                    files = os.listdir(upload_folder)
                    print(f"Files in upload folder: {files}")
                    
                    for filename in files:
                        filepath = os.path.join(upload_folder, filename)
                        if os.path.isfile(filepath) and not filename.startswith('.'):
                            # Get file info
                            size = os.path.getsize(filepath)
                            mod_time = os.path.getmtime(filepath)
                            upload_date = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M')
                            
                            # Get document info from database if available
                            db_doc = Document.query.filter_by(filename=filename).first()
                            if db_doc and db_doc.upload_date:
                                upload_date = db_doc.upload_date.strftime('%Y-%m-%d %H:%M')
                            
                            # Format file size
                            if size < 1024:
                                size_str = f"{size} B"
                            elif size < 1024 * 1024:
                                size_str = f"{size/1024:.1f} KB"
                            else:
                                size_str = f"{size/(1024*1024):.1f} MB"
                            
                            documents.append({
                                'filename': filename,
                                'size': size_str,
                                'upload_date': upload_date
                            })
                
                print(f"Documents found: {len(documents)}")
                
            except Exception as e:
                print(f"Error loading admin data: {e}")
                import traceback
                traceback.print_exc()
                flash("Error loading admin data", "danger")
        
        # Process search if query exists
        if query:
            if not whoosh_index.exists_in(INDEX_DIR):
                flash("Search index not available. Please upload documents first.", "warning")
            else:
                try:
                    ix = whoosh_index.open_dir(INDEX_DIR)
                    with ix.searcher() as searcher:
                        from whoosh.qparser import MultifieldParser
                        parser = MultifieldParser(["filename", "content"], schema=ix.schema)
                        query_obj = parser.parse(query)
                        hits = searcher.search(query_obj, limit=5)
                        
                        for hit in hits:
                            filepath = os.path.join(app.config['UPLOAD_FOLDER'], hit['filename'])
                            if os.path.exists(filepath):
                                try:
                                    with open(filepath, 'r', encoding='utf-8') as f:
                                        file_content = f.read()
                                except UnicodeDecodeError:
                                    with open(filepath, 'r', encoding='latin-1') as f:
                                        file_content = f.read()
                                
                                snippets = get_highlighted_snippets(file_content, query)
                                results.append({
                                    'filename': hit['filename'],
                                    'snippets': snippets['snippets'],
                                    'count': snippets['occurrence_count'],
                                    'view_link': url_for('view_document', filename=hit['filename'], q=query)
                                })

                except Exception as e:
                    logger.error(f"Search error: {e}")
                    flash("An error occurred during search", "danger")
        
        return render_template('pages/home.html',
                            users=users,
                            query=query,
                            results=results,
                            documents=documents,
                            is_admin=is_admin)

    except Exception as e:
        logger.error(f"Home route error: {e}")
        import traceback
        traceback.print_exc()
        flash("An unexpected error occurred", "danger")
        return render_template('pages/home.html',
                            users=[],
                            query='',
                            results=[],
                            documents=[],
                            is_admin=session.get('is_admin', False))

@app.route('/test-db')
def test_db():
    """Test database connection"""
    try:
        # Try to execute a simple query
        result = db.session.execute('SELECT 1').scalar()
        return f"Database connection successful: {result}"
    except Exception as e:
        return f"Database connection failed: {str(e)}", 500

@app.route('/about')
def about():
    """About page."""
    return render_template('pages/about.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    User registration. On POST, create a new user or flash error.
    """
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        hashed_pw = generate_password_hash(request.form['password'])

        try:
            db.session.add(User(username=username, email=email, password=hashed_pw))
            db.session.commit()
            flash('Account created! You can now log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Email or username already registered.', 'danger')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Signup error: {e}")
            flash('An error occurred. Try again.', 'danger')

    return render_template('pages/signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login. On POST, validate credentials and set session.
    """
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, request.form['password']):
            session.update({
                'user_id': user.id,
                'username': user.username,
                'is_admin': user.is_admin
            })
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        flash('Invalid credentials.', 'danger')

    return render_template('pages/login.html')


@app.route('/logout')
def logout():
    """Log out the current user."""
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))


@app.route('/upload', methods=['GET', 'POST'])
def upload_document():
    """
    Document upload: save text/csv files, index them, and record in DB.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        files = request.files.getlist('file')
        if not files or not files[0].filename:
            flash("No files selected for upload.", 'info')
        else:
            uploaded, failed = 0, 0
            for file in files:
                if file.filename.lower().endswith(('.txt', '.csv')):
                    path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                    try:
                        file.save(path)
                        db.session.add(Document(
                            filename=file.filename,
                            uploaded_by=session['user_id']
                        ))
                        index_document(file.filename, path)
                        uploaded += 1
                    except Exception as e:
                        logger.error(f"Upload error for {file.filename}: {e}")
                        flash(f"Error uploading {file.filename}.", 'danger')
                        db.session.rollback()
                        failed += 1
                else:
                    flash(f"Invalid file type: {file.filename}", 'warning')
                    failed += 1
            
            if uploaded:
                try:
                    db.session.commit()
                    flash(f"{uploaded} file(s) uploaded.", 'success')
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Database commit error: {e}")
                    flash("Error saving document information.", 'danger')
            
            if failed:
                flash(f"{failed} file(s) failed.", 'danger')
        
        # Always redirect after POST to prevent duplicate submissions
        return redirect(url_for('upload_document'))

    # GET request - show upload form
    documents = Document.query.order_by(Document.upload_date.desc()).all()
    return render_template('pages/upload.html', documents=documents)

@app.route('/debug/index')
def debug_index():
    """Debug route to check index contents"""
    if not whoosh_index.exists_in(INDEX_DIR):
        return "Index does not exist", 404
        
    ix = whoosh_index.open_dir(INDEX_DIR)
    with ix.searcher() as searcher:
        return jsonify({
            "doc_count": searcher.doc_count(),
            "fields": list(ix.schema.names()),
            "documents": list(searcher.documents())
        })

@app.route('/debug/files')
def debug_files():
    """Debug route to check uploaded files"""
    files = []
    for fname in os.listdir(app.config['UPLOAD_FOLDER']):
        path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
        files.append({
            "name": fname,
            "size": os.path.getsize(path),
            "exists": os.path.exists(path)
        })
    return jsonify(files)

@app.route('/download/<filename>')
def download_file(filename):
    """Serve uploaded files for download."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/view_document/<filename>')
def view_document(filename):
    """
    Display the contents of a text document in a separate page.
    """
    # Security check: prevent directory traversal
    if '..' in filename or filename.startswith('/'):
        return "Invalid filename", 400
    
    # Get search query if any for highlighting
    query = request.args.get('q', '').strip()
    
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Check if file exists
    if not os.path.exists(path):
        return render_template('404.html'), 404
    
    try:
        # Try different encodings to handle various file types
        encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
        content = None
        
        for encoding in encodings:
            try:
                with open(path, 'r', encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            return "Unable to read file (encoding issue)", 500
        
        # If there's a search query, highlight the matches
        highlighted_content = content
        if query:
            # Simple highlighting implementation
            for term in query.split():
                try:
                    pattern = re.compile(re.escape(term), re.IGNORECASE)
                    highlighted_content = pattern.sub(r'<mark>\g<0></mark>', highlighted_content)
                except re.error:
                    # Handle regex errors for problematic terms
                    continue
        
        return render_template('pages/view_document.html',
                               filename=filename,
                               content=highlighted_content,
                               query=query)
    except Exception as e:
        logger.error(f"View error for {filename}: {e}")
        return "Error viewing document.", 500


@app.route('/search')
def search():
    """
    Full-text search route using Whoosh. Returns up to 10 results with highlighted snippets.
    """
    query = request.args.get('q', '').strip()
    results = []
    if query:
        try:
            ix = whoosh_index.open_dir(INDEX_DIR)
            with ix.searcher() as searcher:
                parser = QueryParser("content", schema=ix.schema)
                hits = searcher.search(parser.parse(query), limit=10)
                for hit in hits:
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], hit['filename'])
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    snippet_data = get_highlighted_snippets(content, query)
                    results.append({
                        'filename': hit['filename'],
                        'snippets': snippet_data['snippets'],
                        'occurrence_count': snippet_data['occurrence_count'],
                        'view_link': url_for('view_document', filename=hit['filename'], q=query),
                        'download_link': url_for('download_file', filename=hit['filename'])
                    })
        except Exception as e:
            logger.error(f"Search error: {e}")
            results.append({
                'filename': "Error",
                'snippets': ["An error occurred during search."],
                'occurrence_count': 0
            })

    return render_template('pages/results.html', query=query, results=results, corrected=None)

# -------------------- Custom Dictionary API --------------------

@app.route('/add_to_dictionary', methods=['POST'])
def add_to_dictionary():
    """
    AJAX endpoint: add a word to the logged-in user's custom dictionary.
    """
    word = request.form['word']
    if 'user_id' not in session:
        return jsonify(success=False, message="Login required"), 401

    user_id = session['user_id']
    existing = CustomDictionary.query.filter_by(user_id=user_id, word=word).first()
    if existing:
        return jsonify(success=False, message=f"'{word}' is already in your dictionary.")

    try:
        db.session.add(CustomDictionary(user_id=user_id, word=word))
        db.session.commit()
        return jsonify(success=True, message=f"'{word}' added to dictionary.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding to dictionary: {e}")
        return jsonify(success=False, message="Could not add word."), 500


# -------------------- Admin Routes --------------------

@app.route('/admin/users/add', methods=['GET', 'POST'])
def admin_add_user():
    """
    Admin-only: create new user accounts.
    """
    if not session.get('is_admin'):
        flash("Unauthorized.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        user = User(
            username=request.form['username'],
            email=request.form['email'],
            password=generate_password_hash(request.form['password']),
            is_admin=request.form.get('is_admin') == 'on'
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash("User created successfully!", "success")
            return redirect(url_for('home'))
        except IntegrityError:
            db.session.rollback()
            flash("Email or username already registered.", "danger")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Admin add user error: {e}")
            flash("An unexpected error occurred.", "danger")

    return render_template('pages/admin_add_user.html')


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    """
    Admin-only: edit existing user details.
    """
    if not session.get('is_admin'):
        flash("Unauthorized.", "danger")
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        pw = request.form.get('password')
        if pw:
            user.password = generate_password_hash(pw)
        user.is_admin = request.form.get('is_admin') == 'on'
        try:
            db.session.commit()
            flash("User updated successfully!", "success")
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Admin edit user error: {e}")
            flash("Error updating user.", "danger")

    return render_template('pages/admin_edit_user.html', user=user)


@app.route('/admin/delete_document/<filename>', methods=['POST'])
def admin_delete_document(filename):
    if not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    
    # Security check to prevent path traversal
    if '..' in filename or filename.startswith('/') or '/' in filename:
        flash('Invalid filename', 'error')
        return redirect(url_for('home'))
    
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if os.path.exists(filepath):
            # Remove from filesystem
            os.remove(filepath)
            
            # Remove from search index if you have one
            if whoosh_index.exists_in(INDEX_DIR):
                ix = whoosh_index.open_dir(INDEX_DIR)
                writer = ix.writer()
                writer.delete_by_term('filename', filename)
                writer.commit()
            
            # Remove from database
            Document.query.filter_by(filename=filename).delete()
            db.session.commit()
            
            flash(f'Document {filename} deleted successfully', 'success')
        else:
            flash('Document not found', 'error')
    
    except Exception as e:
        logger.error(f"Error deleting document {filename}: {e}")
        flash(f'Error deleting document: {str(e)}', 'danger')
    
    return redirect(url_for('home'))

@app.route('/admin/documents/clear', methods=['POST'])
def admin_clear_documents():
    """
    Admin-only: Delete all documents, clear uploads and Whoosh index.
    """
    if not session.get('is_admin'):
        flash("Unauthorized.", "danger")
        return redirect(url_for('home'))

    try:
        count = Document.query.delete()
        db.session.commit()

        # Remove all files from upload directory
        for fname in os.listdir(app.config['UPLOAD_FOLDER']):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], fname))

        # Recreate Whoosh index
        shutil.rmtree(INDEX_DIR, ignore_errors=True)
        os.makedirs(INDEX_DIR, exist_ok=True)
        schema = Schema(filename=ID(stored=True), content=TEXT)
        whoosh_index.create_in(INDEX_DIR, schema)
        flash(f"Cleared {count} documents and reset index.", "success")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Admin clear documents error: {e}")
        flash("Error clearing documents.", "danger")

    return redirect(url_for('home'))

@app.route('/debug/db')
def debug_db():
    """Debug route to check database contents"""
    if not session.get('is_admin'):
        return "Admin access required", 403
    
    users = User.query.all()
    documents = Document.query.all()
    
    return jsonify({
        "users": [{"id": u.id, "username": u.username, "email": u.email, "is_admin": u.is_admin} for u in users],
        "documents": [{"id": d.id, "filename": d.filename, "upload_date": str(d.upload_date)} for d in documents],
        "user_count": len(users),
        "document_count": len(documents)
    })

@app.route('/check-admin')
def check_admin():
    """Check if current user is admin"""
    return jsonify({
        'is_admin': session.get('is_admin', False),
        'user_id': session.get('user_id'),
        'username': session.get('username')
    })

@app.route('/debug/session')
def debug_session():
    """Debug session data"""
    return jsonify(dict(session))

@app.route('/debug/upload-folder')
def debug_upload_folder():
    """Debug upload folder contents"""
    if not session.get('is_admin'):
        return "Admin access required", 403
    
    upload_path = app.config['UPLOAD_FOLDER']
    files = []
    
    if os.path.exists(upload_path):
        for f in os.listdir(upload_path):
            filepath = os.path.join(upload_path, f)
            if os.path.isfile(filepath):
                files.append({
                    'name': f,
                    'size': os.path.getsize(filepath),
                    'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                })
    
    return jsonify({
        'upload_path': upload_path,
        'exists': os.path.exists(upload_path),
        'files': files
    })

# Add this debug route to check the actual table names
@app.route('/debug/tables')
def debug_tables():
    """Debug route to check database table structure"""
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    
    result = {}
    for table in tables:
        columns = inspector.get_columns(table)
        result[table] = [col['name'] for col in columns]
    
    return jsonify(result)

# -------------------- Error Handlers --------------------

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# -------------------- Run Application --------------------

if __name__ == '__main__':
    app.run(debug=True)