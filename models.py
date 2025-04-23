from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

database = SQLAlchemy()

class RegisteredApp(database.Model):
    __tablename__ = 'registered_apps'
    id = database.Column(database.Integer, primary_key=True)
    app_name = database.Column(database.String(100), unique=True, nullable=False)
    client_id = database.Column(database.String(100), unique=True, nullable=False)
    client_secret_hash = database.Column(database.String(200), nullable=False)
    redirect_uris = database.Column(database.Text, nullable=False)
    scopes = database.Column(database.Text, nullable=False)
    logo_uri = database.Column(database.String(255))
    contacts = database.Column(database.Text)
    tos_uri = database.Column(database.String(255))
    policy_uri = database.Column(database.String(255))
    jwks_uri = database.Column(database.String(255))
    date_registered = database.Column(database.DateTime, default=datetime.utcnow)
    last_updated = database.Column(database.DateTime, onupdate=datetime.utcnow)
    is_test_app = database.Column(database.Boolean, default=False)
    test_app_expires_at = database.Column(database.DateTime)

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.redirect_uris.split(',')[0] if self.redirect_uris else None

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris.split(',')

    def check_response_type(self, response_type):
        return response_type == 'code'

    def check_grant_type(self, grant_type):
        return grant_type in ['authorization_code', 'refresh_token']

    def check_endpoint_auth_method(self, method, endpoint):
        return method in ['client_secret_post', 'client_secret_basic']

    def get_allowed_scope(self, scopes):
        allowed = set(self.scopes.split())
        requested = set(scopes.split())
        return ' '.join(sorted(allowed.intersection(requested)))

    def set_client_secret(self, client_secret):
        self.client_secret_hash = generate_password_hash(client_secret)

    def check_client_secret(self, client_secret):
        return check_password_hash(self.client_secret_hash, client_secret)

class OAuthToken(database.Model):
    __tablename__ = 'oauth_tokens'
    id = database.Column(database.Integer, primary_key=True)
    client_id = database.Column(database.String(100), nullable=False)
    token_type = database.Column(database.String(40))
    access_token = database.Column(database.String(255), nullable=False)
    refresh_token = database.Column(database.String(255))
    scope = database.Column(database.Text)
    issued_at = database.Column(database.Integer, nullable=False)
    expires_in = database.Column(database.Integer, nullable=False)

class AuthorizationCode(database.Model):
    __tablename__ = 'authorization_codes'
    id = database.Column(database.Integer, primary_key=True)
    code = database.Column(database.String(255), nullable=False)
    client_id = database.Column(database.String(100), database.ForeignKey('registered_apps.client_id', name='fk_authorization_codes_client_id'), nullable=False)
    redirect_uri = database.Column(database.Text)
    scope = database.Column(database.Text)
    nonce = database.Column(database.String(255))
    code_challenge = database.Column(database.String(255))
    code_challenge_method = database.Column(database.String(10))
    response_type = database.Column(database.String(40))
    state = database.Column(database.String(255))
    issued_at = database.Column(database.Integer, nullable=False)
    expires_at = database.Column(database.Integer, nullable=False)

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

class Configuration(database.Model):
    __tablename__ = 'configurations'
    id = database.Column(database.Integer, primary_key=True)
    key = database.Column(database.String(100), unique=True, nullable=False)
    value = database.Column(database.Text, nullable=False)
    description = database.Column(database.Text)
    last_updated = database.Column(database.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)