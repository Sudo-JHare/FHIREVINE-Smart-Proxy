import os
import sys
import logging
import secrets
import base64
import hashlib
import requests
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app
from flask_migrate import Migrate
from flasgger import Swagger, swag_from
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
from forms import FlaskForm
from sqlalchemy.exc import OperationalError
from sqlalchemy import text
from wtforms import StringField, URLField, SubmitField
from wtforms.validators import DataRequired, URL

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import database, RegisteredApp, OAuthToken, AuthorizationCode, Configuration
from forms import RegisterAppForm, TestClientForm, SecurityConfigForm, ProxyConfigForm, EndpointConfigForm, ConsentForm
from smart_proxy import smart_blueprint, configure_oauth

load_dotenv()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

migrate = Migrate()

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key-for-fhirvine'),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', f'sqlite:///{os.path.join(app.instance_path, "fhirvine.db")}'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        FHIR_SERVER_URL=os.environ.get('FHIR_SERVER_URL', 'http://hapi.fhir.org/baseR4'),
        PROXY_TIMEOUT=10,
        METADATA_ENDPOINT='/metadata',
        CAPABILITY_ENDPOINT='/metadata',
        RESOURCE_BASE_ENDPOINT='',
        TOKEN_DURATION=3600,
        REFRESH_TOKEN_DURATION=86400,
        ALLOWED_SCOPES='openid profile launch launch/patient patient/*.read offline_access',
        WTF_CSRF_ENABLED=True
    )

    if not app.config['SECRET_KEY']:
        logger.error("SECRET_KEY is not set. CSRF protection may fail.")
    else:
        logger.debug(f"SECRET_KEY is set: {app.config['SECRET_KEY'][:8]}...")

    try:
        os.makedirs(app.instance_path, exist_ok=True)
        logger.info(f"Instance path created/verified: {app.instance_path}")
        logger.info(f"Database URI set to: {app.config['SQLALCHEMY_DATABASE_URI']}")
    except OSError as e:
        logger.error(f"Could not create instance path at {app.instance_path}: {e}", exc_info=True)

    database.init_app(app)
    migrate.init_app(app, database)

    swagger_template = {
        "info": {
            "title": "FHIRVINE SMART on FHIR Proxy API",
            "version": "1.0",
            "description": "API for SMART on FHIR SSO proxy functionality."
        },
        "host": "localhost:5001",
        "basePath": "/oauth2",
        "schemes": ["http"]
    }
    swagger_config = {
        "specs": [
            {
                "endpoint": "apispec_1",
                "route": "/apispec/1",
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }
        ],
        "uimode": "view",
        "specs_route": "/apispec/",
        "headers": []
    }
    swagger = Swagger(app, template=swagger_template, config=swagger_config)

    configure_oauth(app, db=database, registered_app_model=RegisteredApp, oauth_token_model=OAuthToken, auth_code_model=AuthorizationCode)

    app.register_blueprint(smart_blueprint, url_prefix='/oauth2')

    def load_config_from_db():
        try:
            configs = Configuration.query.all()
            logger.debug(f"Loaded configs from database: {[{'key': c.key, 'value': c.value} for c in configs]}")
            for config in configs:
                try:
                    app.config[config.key] = int(config.value) if config.key in ['TOKEN_DURATION', 'PROXY_TIMEOUT', 'REFRESH_TOKEN_DURATION'] else config.value
                except ValueError:
                    app.config[config.key] = config.value
        except OperationalError as e:
            logger.warning(f"Could not load configurations from database: {e}. Using default config values.")

    def get_config_value(key, default):
        try:
            # Ensure the session is fresh
            database.session.expire_all()
            config = Configuration.query.filter_by(key=key).first()
            if config:
                logger.debug(f"Retrieved {key} from database (exact match): {config.value}")
                return int(config.value) if key in ['TOKEN_DURATION', 'PROXY_TIMEOUT', 'REFRESH_TOKEN_DURATION'] else config.value
            # Try case-insensitive match
            config = Configuration.query.filter(Configuration.key.ilike(key)).first()
            if config:
                logger.debug(f"Retrieved {key} from database (case-insensitive match): {config.value}")
                return int(config.value) if key in ['TOKEN_DURATION', 'PROXY_TIMEOUT', 'REFRESH_TOKEN_DURATION'] else config.value
            # Fallback: Direct database query
            result = database.session.execute(
                text("SELECT value FROM configurations WHERE key = :key"),
                {"key": key}
            ).fetchone()
            if result:
                value = result[0]
                logger.debug(f"Retrieved {key} from database (direct query): {value}")
                return int(value) if key in ['TOKEN_DURATION', 'PROXY_TIMEOUT', 'REFRESH_TOKEN_DURATION'] else value
            logger.debug(f"No value found in database for {key}, using default: {default}")
        except OperationalError as e:
            logger.error(f"Database error while retrieving {key}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error while retrieving {key}: {e}")
        return default

    with app.app_context():
        load_config_from_db()

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/app-gallery')
    def app_gallery():
        form = FlaskForm()
        try:
            apps = RegisteredApp.query.order_by(RegisteredApp.app_name).all()
            apps = [app for app in apps if app.is_test_app is None or app.is_test_app == False or app.test_app_expires_at > datetime.utcnow()]
            logger.debug(f"App gallery apps retrieved: {[{'id': app.id, 'app_name': app.app_name, 'client_id': app.client_id, 'is_test_app': app.is_test_app, 'test_app_expires_at': app.test_app_expires_at} for app in apps]}")
        except Exception as e:
            logger.error(f"Error fetching apps from database: {e}", exc_info=True)
            flash("Could not load application gallery. Please try again later.", "error")
            apps = []
        return render_template('app_gallery/gallery.html', apps=apps, form=form)

    @app.route('/register-app', methods=['GET', 'POST'])
    def register_app():
        form = RegisterAppForm()
        is_test = request.args.get('test', '0') == '1'
        if form.validate_on_submit():
            try:
                client_id = secrets.token_urlsafe(32)
                redirect_uris = form.redirect_uris.data.strip().lower()
                new_app = RegisteredApp(
                    app_name=form.app_name.data,
                    client_id=client_id,
                    redirect_uris=redirect_uris,
                    scopes=form.scopes.data.strip(),
                    logo_uri=form.logo_uri.data or None,
                    contacts=form.contacts.data.strip() or None,
                    tos_uri=form.tos_uri.data or None,
                    policy_uri=form.policy_uri.data or None,
                    is_test_app=is_test,
                    test_app_expires_at=datetime.utcnow() + timedelta(hours=24) if is_test else None
                )
                client_secret = secrets.token_urlsafe(40)
                new_app.set_client_secret(client_secret)
                database.session.add(new_app)
                database.session.commit()
                flash(f"Application '{new_app.app_name}' registered successfully!", "success")
                flash(f"Client ID: {new_app.client_id}", "info")
                flash(f"Client Secret: {client_secret} (Please store this securely!)", "warning")
                logger.info(f"Registered new app: {new_app.app_name} (ID: {new_app.id}, ClientID: {new_app.client_id}, IsTest: {new_app.is_test_app}, ExpiresAt: {new_app.test_app_expires_at}, LogoURI: {new_app.logo_uri}, TosURI: {new_app.tos_uri}, PolicyURI: {new_app.policy_uri})")
                return redirect(url_for('app_gallery'))
            except Exception as e:
                database.session.rollback()
                logger.error(f"Error registering application '{form.app_name.data}': {e}", exc_info=True)
                flash(f"Error registering application: {e}", "error")
        return render_template('app_gallery/register.html', form=form, is_test=is_test)

    @app.route('/edit-app/<int:app_id>', methods=['GET', 'POST'])
    def edit_app(app_id):
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
        app = RegisteredApp.query.get_or_404(app_id)
        form = FlaskForm()
        if form.validate_on_submit():
            try:
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
        return render_template('app_gallery/delete.html', app=app, form=form)

    @app.route('/test-client', methods=['GET', 'POST'])
    def test_client():
        form = TestClientForm()
        response_data = None
        response_mode = session.get('response_mode', 'inline')
        logger.debug(f"Session contents before form submission: {session}")
        if form.validate_on_submit():
            client_id = form.client_id.data
            app = RegisteredApp.query.filter_by(client_id=client_id).first()
            if not app:
                flash("Invalid Client ID.", "error")
                return redirect(url_for('test_client'))
            response_mode = form.response_mode.data if hasattr(form, 'response_mode') and form.response_mode.data else 'inline'
            session['response_mode'] = response_mode
            scopes = ' '.join(set(app.scopes.split()))
            code_verifier = secrets.token_urlsafe(32)
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode('ascii')).digest()
            ).decode('ascii').rstrip('=')
            session['code_verifier'] = code_verifier
            redirect_uri = app.get_default_redirect_uri().lower()
            auth_url = url_for(
                'smart_proxy.authorize',
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scopes,
                response_type='code',
                state='test_state_123',
                aud=current_app.config['FHIR_SERVER_URL'] + current_app.config['METADATA_ENDPOINT'],
                code_challenge=code_challenge,
                code_challenge_method='S256',
                _external=True
            )
            logger.info(f"Redirecting to authorization URL for client '{client_id}'")
            logger.info(f"Code verifier for client '{client_id}': {code_verifier}")
            session['post_auth_redirect'] = redirect_uri
            return redirect(auth_url)
        if 'code' in request.args and 'state' in request.args:
            code = request.args.get('code')
            state = request.args.get('state')
            redirect_uri = session.get('post_auth_redirect')
            if redirect_uri:
                if response_mode == 'redirect':
                    redirect_url = f"{redirect_uri}?code={code}&state={state}"
                    session.pop('post_auth_redirect', None)
                    session.pop('response_mode', None)
                    return redirect(redirect_url)
                else:
                    try:
                        response = requests.get(redirect_uri, params={'code': code, 'state': state})
                        response.raise_for_status()
                        response_data = response.json()
                        logger.debug(f"Received response from redirect_uri: {response_data}")
                    except requests.RequestException as e:
                        logger.error(f"Error fetching response from redirect_uri: {e}")
                        flash(f"Error fetching response from redirect_uri: {e}", "error")
                    finally:
                        session.pop('post_auth_redirect', None)
                        session.pop('response_mode', None)
        try:
            apps = RegisteredApp.query.filter(
                (RegisteredApp.is_test_app == False) |
                (RegisteredApp.is_test_app.is_(None)) |
                (RegisteredApp.test_app_expires_at > datetime.utcnow())
            ).all()
            logger.debug(f"Test client apps retrieved: {[{'id': app.id, 'app_name': app.app_name, 'client_id': app.client_id, 'is_test_app': app.is_test_app, 'test_app_expires_at': app.test_app_expires_at} for app in apps]}")
        except Exception as e:
            logger.error(f"Error fetching apps for test client: {e}", exc_info=True)
            flash("Could not load applications. Please try again later.", "error")
            apps = []
        return render_template('test_client.html', form=form, apps=apps, response_data=response_data, response_mode=response_mode)

    @app.route('/test-server', methods=['GET', 'POST'])
    def test_server():
        class ServerTestForm(FlaskForm):
            client_id = StringField('Client ID', validators=[DataRequired()])
            client_secret = StringField('Client Secret', validators=[DataRequired()])
            redirect_uri = URLField('Redirect URI', validators=[DataRequired(), URL()])
            scopes = StringField('Scopes (Space-separated)', validators=[DataRequired()], default='openid profile launch launch/patient patient/*.read offline_access')
            submit = SubmitField('Initiate Authorization')

        form = ServerTestForm()
        response_data = None
        if form.validate_on_submit():
            try:
                client_id = form.client_id.data
                client_secret = form.client_secret.data
                redirect_uri = form.redirect_uri.data
                scopes = ' '.join(set(form.scopes.data.split()))
                code_verifier = secrets.token_urlsafe(32)
                code_challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode('ascii')).digest()
                ).decode('ascii').rstrip('=')
                session['server_test_code_verifier'] = code_verifier
                session['server_test_client_secret'] = client_secret
                auth_url = url_for(
                    'smart_proxy.authorize',
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    scope=scopes,
                    response_type='code',
                    state='server_test_state',
                    aud=current_app.config['FHIR_SERVER_URL'] + current_app.config['METADATA_ENDPOINT'],
                    code_challenge=code_challenge,
                    code_challenge_method='S256',
                    _external=True
                )
                session['server_test_redirect_uri'] = redirect_uri
                return redirect(auth_url)
            except Exception as e:
                flash(f"Error initiating authorization: {e}", "error")
                logger.error(f"Error in test-server: {e}", exc_info=True)
        if 'code' in request.args and 'state' in request.args and request.args.get('state') == 'server_test_state':
            code = request.args.get('code')
            redirect_uri = session.get('server_test_redirect_uri')
            client_secret = session.get('server_test_client_secret')
            code_verifier = session.get('server_test_code_verifier')
            if redirect_uri and client_secret and code_verifier:
                token_url = url_for('smart_proxy.issue_token', _external=True)
                token_data = {
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': redirect_uri,
                    'client_id': form.client_id.data,
                    'client_secret': client_secret,
                    'code_verifier': code_verifier
                }
                try:
                    response = requests.post(token_url, data=token_data)
                    response.raise_for_status()
                    response_data = response.json()
                    response_data['token_request'] = token_data
                    logger.debug(f"Token response: {response_data}")
                except requests.RequestException as e:
                    flash(f"Error exchanging code for token: {e}", "error")
                    logger.error(f"Error exchanging code for token: {e}", exc_info=True)
                finally:
                    session.pop('server_test_redirect_uri', None)
                    session.pop('server_test_client_secret', None)
                    session.pop('server_test_code_verifier', None)
        return render_template('test_server.html', form=form, response_data=response_data)

    @app.route('/configure/security', methods=['GET', 'POST'])
    def security_settings():
        token_duration = get_config_value('TOKEN_DURATION', 3600)
        refresh_token_duration = get_config_value('REFRESH_TOKEN_DURATION', 86400)
        allowed_scopes = get_config_value('ALLOWED_SCOPES', 'openid profile launch launch/patient patient/*.read offline_access')
        form = SecurityConfigForm()
        form_data = {
            'token_duration': token_duration,
            'refresh_token_duration': refresh_token_duration,
            'allowed_scopes': allowed_scopes
        }
        logger.debug(f"Security form data: {form_data}")
        form.process(data=form_data)
        # Fallback: Directly set form field values
        form.token_duration.data = token_duration
        form.refresh_token_duration.data = refresh_token_duration
        form.allowed_scopes.data = allowed_scopes
        logger.debug(f"Security form fields after process: {list(form._fields.keys())}")
        logger.debug(f"Security form values before render: token_duration={form.token_duration.data}, refresh_token_duration={form.refresh_token_duration.data}, allowed_scopes={form.allowed_scopes.data}")
        if form.validate_on_submit():
            try:
                configs = [
                    Configuration(key='TOKEN_DURATION', value=str(form.token_duration.data), description='Access token duration in seconds'),
                    Configuration(key='REFRESH_TOKEN_DURATION', value=str(form.refresh_token_duration.data), description='Refresh token duration in seconds'),
                    Configuration(key='ALLOWED_SCOPES', value=form.allowed_scopes.data.strip(), description='Allowed OAuth2 scopes')
                ]
                for config in configs:
                    existing = Configuration.query.filter_by(key=config.key).first()
                    if existing:
                        existing.value = config.value
                        existing.description = config.description
                    else:
                        database.session.add(config)
                database.session.commit()
                load_config_from_db()
                flash("Security settings updated successfully!", "success")
                return redirect(url_for('security_settings'))
            except Exception as e:
                database.session.rollback()
                logger.error(f"Error updating security settings: {e}", exc_info=True)
                flash(f"Error updating security settings: {e}", "error")
        return render_template('configure/security.html', form=form)

    @app.route('/configure/proxy-settings', methods=['GET', 'POST'])
    def proxy_settings():
        fhir_server_url = get_config_value('FHIR_SERVER_URL', 'http://hapi.fhir.org/baseR4')
        proxy_timeout = get_config_value('PROXY_TIMEOUT', 10)
        form = ProxyConfigForm()
        form_data = {
            'fhir_server_url': fhir_server_url,
            'proxy_timeout': proxy_timeout
        }
        logger.debug(f"Proxy settings form data: {form_data}")
        form.process(data=form_data)
        # Fallback: Directly set form field values
        form.fhir_server_url.data = fhir_server_url
        form.proxy_timeout.data = proxy_timeout
        logger.debug(f"Proxy settings form fields after process: {list(form._fields.keys())}")
        logger.debug(f"Proxy settings form values before render: fhir_server_url={form.fhir_server_url.data}, proxy_timeout={form.proxy_timeout.data}")
        if form.validate_on_submit():
            try:
                configs = [
                    Configuration(key='FHIR_SERVER_URL', value=form.fhir_server_url.data.strip(), description='Upstream FHIR server URL'),
                    Configuration(key='PROXY_TIMEOUT', value=str(form.proxy_timeout.data), description='Proxy request timeout in seconds')
                ]
                for config in configs:
                    existing = Configuration.query.filter_by(key=config.key).first()
                    if existing:
                        existing.value = config.value
                        existing.description = config.description
                    else:
                        database.session.add(config)
                database.session.commit()
                load_config_from_db()
                flash("Proxy settings updated successfully!", "success")
                return redirect(url_for('proxy_settings'))
            except Exception as e:
                database.session.rollback()
                logger.error(f"Error updating proxy settings: {e}", exc_info=True)
                flash(f"Error updating proxy settings: {e}", "error")
        return render_template('configure/proxy_settings.html', form=form, fhir_server_url=app.config['FHIR_SERVER_URL'])

    @app.route('/configure/server-endpoints', methods=['GET', 'POST'])
    def server_endpoints():
        metadata_endpoint = get_config_value('METADATA_ENDPOINT', '/metadata')
        capability_endpoint = get_config_value('CAPABILITY_ENDPOINT', '/metadata')
        resource_base_endpoint = get_config_value('RESOURCE_BASE_ENDPOINT', '')
        form = EndpointConfigForm()
        form_data = {
            'metadata_endpoint': metadata_endpoint,
            'capability_endpoint': capability_endpoint,
            'resource_base_endpoint': resource_base_endpoint
        }
        logger.debug(f"Server endpoints form data: {form_data}")
        form.process(data=form_data)
        # Fallback: Directly set form field values
        form.metadata_endpoint.data = metadata_endpoint
        form.capability_endpoint.data = capability_endpoint
        form.resource_base_endpoint.data = resource_base_endpoint
        logger.debug(f"Server endpoints form fields after process: {list(form._fields.keys())}")
        logger.debug(f"Server endpoints form values before render: metadata_endpoint={form.metadata_endpoint.data}, capability_endpoint={form.capability_endpoint.data}, resource_base_endpoint={form.resource_base_endpoint.data}")
        if form.validate_on_submit():
            try:
                configs = [
                    Configuration(
                        key='METADATA_ENDPOINT',
                        value=form.metadata_endpoint.data.strip(),
                        description='FHIR server metadata endpoint'
                    ),
                    Configuration(
                        key='CAPABILITY_ENDPOINT',
                        value=form.capability_endpoint.data.strip(),
                        description='FHIR server capability statement endpoint'
                    ),
                    Configuration(
                        key='RESOURCE_BASE_ENDPOINT',
                        value=form.resource_base_endpoint.data.strip(),
                        description='Base path for FHIR resources'
                    )
                ]
                for config in configs:
                    existing = Configuration.query.filter_by(key=config.key).first()
                    if existing:
                        existing.value = config.value
                        existing.description = config.description
                    else:
                        database.session.add(config)
                database.session.commit()
                load_config_from_db()
                flash("Endpoint settings updated successfully!", "success")
                return redirect(url_for('server_endpoints'))
            except Exception as e:
                database.session.rollback()
                logger.error(f"Error updating endpoint settings: {e}", exc_info=True)
                flash(f"Error updating endpoint settings: {e}", "error")
        return render_template('configure/server_endpoints.html', form=form)

    @app.route('/api-docs')
    @swag_from({
        'tags': ['Documentation'],
        'summary': 'API Documentation',
        'description': 'Swagger UI for FHIRVINE API documentation.',
        'responses': {
            '200': {
                'description': 'Renders the Swagger UI documentation page.'
            }
        }
    })
    def custom_apidocs():
        return render_template('swagger-ui.html')

    @app.route('/about')
    def about():
        return render_template('about.html')

    @app.context_processor
    def inject_site_name():
        return dict(site_name='FHIRVINE SMART Proxy')

    @app.errorhandler(404)
    def not_found(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template('errors/500.html'), 500

    logger.info("FHIRVINE Flask application created and configured.")
    return app