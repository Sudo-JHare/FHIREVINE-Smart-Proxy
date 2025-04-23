import os
import sys
import logging
import secrets
import base64
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_migrate import Migrate
from flasgger import Swagger
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

# Add current directory to Python path for reliable imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from our modules
from models import database, RegisteredApp, OAuthToken
from forms import RegisterAppForm, TestClientForm
from smart_proxy import smart_blueprint, configure_oauth

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize extensions
migrate = Migrate()

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__, instance_relative_config=True)

    # Configuration
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key-for-fhirvine'),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', f'sqlite:///{os.path.join(app.instance_path, "fhirvine.db")}'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        # Default proxy settings (can be overridden in .env)
        FHIR_SERVER_URL=os.environ.get('FHIR_SERVER_URL', 'http://hapi.fhir.org/baseR4'),
    )

    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        logger.info(f"Instance path created/verified: {app.instance_path}")
        logger.info(f"Database URI set to: {app.config['SQLALCHEMY_DATABASE_URI']}")
    except OSError as e:
        logger.error(f"Could not create instance path at {app.instance_path}: {e}", exc_info=True)

    # Initialize Flask extensions
    database.init_app(app)
    migrate.init_app(app, database)

    # Initialize Flasgger for OpenAPI
    Swagger(app, template={
        "info": {
            "title": "FHIRVINE SMART on FHIR Proxy API",
            "version": "1.0",
            "description": "API for SMART on FHIR SSO proxy functionality."
        },
        "host": "localhost:5001",
        "basePath": "/oauth2",
        "schemes": ["http"]
    })

    # Configure Authlib
    configure_oauth(app)

    # Register blueprints
    app.register_blueprint(smart_blueprint, url_prefix='/oauth2')

    # Main application routes
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/app-gallery')
    def app_gallery():
        """Display the list of registered applications."""
        try:
            apps = RegisteredApp.query.order_by(RegisteredApp.app_name).all()
        except Exception as e:
            logger.error(f"Error fetching apps from database: {e}", exc_info=True)
            flash("Could not load application gallery. Please try again later.", "error")
            apps = []
        return render_template('app_gallery/gallery.html', apps=apps)

    @app.route('/register-app', methods=['GET', 'POST'])
    def register_app():
        """Handle registration of new applications."""
        form = RegisterAppForm()
        if form.validate_on_submit():
            try:
                # Generate a unique client_id
                client_id = secrets.token_urlsafe(32)
                # Normalize redirect_uris to lowercase
                redirect_uris = form.redirect_uris.data.strip().lower()
                new_app = RegisteredApp(
                    app_name=form.app_name.data,
                    client_id=client_id,
                    redirect_uris=redirect_uris,
                    scopes=form.scopes.data.strip(),
                    logo_uri=form.logo_uri.data or None,
                    contacts=form.contacts.data.strip() or None,
                    tos_uri=form.tos_uri.data or None,
                    policy_uri=form.policy_uri.data or None
                )
                # Generate and hash client secret
                client_secret = secrets.token_urlsafe(40)
                new_app.set_client_secret(client_secret)
                database.session.add(new_app)
                database.session.commit()
                flash(f"Application '{new_app.app_name}' registered successfully!", "success")
                flash(f"Client ID: {new_app.client_id}", "info")
                flash(f"Client Secret: {client_secret} (Please store this securely!)", "warning")
                logger.info(f"Registered new app: {new_app.app_name} (ID: {new_app.id}, ClientID: {new_app.client_id})")
                return redirect(url_for('app_gallery'))
            except Exception as e:
                database.session.rollback()
                logger.error(f"Error registering application '{form.app_name.data}': {e}", exc_info=True)
                flash(f"Error registering application: {e}", "error")
        return render_template('app_gallery/register.html', form=form)

    @app.route('/edit-app/<int:app_id>', methods=['GET', 'POST'])
    def edit_app(app_id):
        """Handle editing of an existing application."""
        app = RegisteredApp.query.get_or_404(app_id)
        form = RegisterAppForm(obj=app)
        if form.validate_on_submit():
            try:
                app.app_name = form.app_name.data
                app.redirect_uris = form.redirect_uris.data.strip().lower()
                app.scopes = form.scopes.data.strip()
                app.logo_uri = form.logo_uri.data or None
                app.contacts = form.contacts.data.strip() or None
                app.tos_uri = form.tos_uri.data or None
                app.policy_uri = form.policy_uri.data or None
                database.session.commit()
                flash(f"Application '{app.app_name}' updated successfully!", "success")
                logger.info(f"Updated app: {app.app_name} (ID: {app.id}, ClientID: {app.client_id})")
                return redirect(url_for('app_gallery'))
            except Exception as e:
                database.session.rollback()
                logger.error(f"Error updating application '{app.app_name}': {e}", exc_info=True)
                flash(f"Error updating application: {e}", "error")
        return render_template('app_gallery/edit.html', form=form, app=app)

    @app.route('/delete-app/<int:app_id>', methods=['GET', 'POST'])
    def delete_app(app_id):
        """Handle deletion of an existing application."""
        app = RegisteredApp.query.get_or_404(app_id)
        if request.method == 'POST':
            try:
                # Delete associated tokens
                OAuthToken.query.filter_by(client_id=app.client_id).delete()
                database.session.delete(app)
                database.session.commit()
                flash(f"Application '{app.app_name}' deleted successfully!", "success")
                logger.info(f"Deleted app: {app.app_name} (ID: {app.id}, ClientID: {app.client_id})")
                return redirect(url_for('app_gallery'))
            except Exception as e:
                database.session.rollback()
                logger.error(f"Error deleting application '{app.app_name}': {e}", exc_info=True)
                flash(f"Error deleting application: {e}", "error")
        return render_template('app_gallery/delete.html', app=app)

    @app.route('/test-client', methods=['GET', 'POST'])
    def test_client():
        """Handle testing of registered SMART app launches."""
        form = TestClientForm()
        if form.validate_on_submit():
            client_id = form.client_id.data
            app = RegisteredApp.query.filter_by(client_id=client_id).first()
            if not app:
                flash("Invalid Client ID.", "error")
                return redirect(url_for('test_client'))
            # Deduplicate scopes
            scopes = ' '.join(set(app.scopes.split()))
            # Generate PKCE code verifier and challenge
            code_verifier = secrets.token_urlsafe(32)
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode('ascii')).digest()
            ).decode('ascii').rstrip('=')
            # Store code verifier in session for /token
            session['code_verifier'] = code_verifier
            # Construct SMART authorization URL, ensuring redirect_uri is lowercase
            redirect_uri = app.get_default_redirect_uri().lower()
            auth_url = url_for(
                'smart_proxy.authorize',
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scopes,
                response_type='code',
                state='test_state_123',
                aud='http://hapi.fhir.org/baseR4/metadata',
                code_challenge=code_challenge,
                code_challenge_method='S256',
                _external=True
            )
            logger.info(f"Redirecting to authorization URL for client '{client_id}'")
            logger.info(f"Code verifier for client '{client_id}': {code_verifier}")
            return redirect(auth_url)
        apps = RegisteredApp.query.all()
        return render_template('test_client.html', form=form, apps=apps)

    @app.route('/configure/proxy-settings')
    def proxy_settings():
        """Display proxy settings page."""
        return render_template('configure/proxy_settings.html', fhir_server_url=app.config['FHIR_SERVER_URL'])

    @app.route('/configure/server-endpoints')
    def server_endpoints():
        """Display server endpoints page."""
        return render_template('configure/server_endpoints.html')

    @app.route('/configure/security')
    def security_settings():
        """Display security settings page."""
        return render_template('configure/security.html')

    @app.route('/about')
    def about():
        """Display about page."""
        return render_template('about.html')

    # Context processors
    @app.context_processor
    def inject_site_name():
        return dict(site_name='FHIRVINE SMART Proxy')

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template('errors/500.html'), 500

    logger.info("FHIRVINE Flask application created and configured.")
    return app