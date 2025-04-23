from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

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
    date_registered = database.Column(database.DateTime)
    last_updated = database.Column(database.DateTime)

    # Authlib ClientMixin methods
    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.redirect_uris.split(',')[0] if self.redirect_uris else None

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris.split(',')

    def check_response_type(self, response_type):
        return response_type == 'code'

    def check_grant_type(self, grant_type):
        # Support authorization_code and refresh_token grants
        return grant_type in ['authorization_code', 'refresh_token']

    def check_endpoint_auth_method(self, method, endpoint):
        # Support client_secret_post and client_secret_basic for token endpoint
        # Currently, we support the same methods for all endpoints
        return method in ['client_secret_post', 'client_secret_basic']

    def get_allowed_scope(self, scopes):
        allowed = set(self.scopes.split())
        requested = set(scopes.split())
        return ' '.join(sorted(allowed.intersection(requested)))

    def set_client_secret(self, client_secret):
        """Set and hash the client secret."""
        self.client_secret_hash = generate_password_hash(client_secret)

    def check_client_secret(self, client_secret):
        """Verify the client secret against the stored hash."""
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

    # Authlib AuthorizationCodeMixin methods
    def get_redirect_uri(self):
        """Return the redirect URI associated with this authorization code."""
        return self.redirect_uri

    def get_scope(self):
        """Return the scope associated with this authorization code."""
        return self.scope