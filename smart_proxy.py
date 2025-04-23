import time
import logging
import secrets
import requests
import base64
import hashlib
from flask import Blueprint, request, session, url_for, render_template, redirect, jsonify, current_app
from flasgger import swag_from
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.sqla_oauth2 import create_query_client_func, create_save_token_func
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6749.errors import OAuth2Error
from werkzeug.http import is_hop_by_hop_header
from forms import ConsentForm

database = None
RegisteredApp = None
OAuthToken = None
AuthorizationCode = None

logger = logging.getLogger(__name__)

smart_blueprint = Blueprint('smart_proxy', __name__, template_folder='templates')

authorization_server = AuthorizationServer()
require_oauth = ResourceProtector()

def query_client(client_id):
    logger.debug(f"Querying client with identifier: {client_id}")
    client = RegisteredApp.query.filter_by(client_id=client_id).first()
    if client:
        logger.debug(f"Found client: {client.app_name} (ClientID: {client.client_id})")
    else:
        logger.warning(f"Client not found for identifier: {client_id}")
    return client

def save_token(token, request):
    client = request.client
    if not client:
        logger.error("No client provided for token saving")
        return
    token_item = OAuthToken(
        client_id=client.client_id,
        token_type=token.get('token_type'),
        access_token=token.get('access_token'),
        refresh_token=token.get('refresh_token'),
        scope=token.get('scope'),
        issued_at=token.get('issued_at'),
        expires_in=token.get('expires_in')
    )
    database.session.add(token_item)
    database.session.commit()
    logger.info(f"Saved token for client '{client.client_id}' with scope: {token.get('scope')}")

def normalize_scopes(scope_string):
    if not scope_string:
        return ''
    return ' '.join(scope_string.replace('+', ' ').split())

class DummyUser:
    def get_user_id(self):
        return "proxy_user"

class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    SUPPORTED_RESPONSE_TYPES = ['code']
    include_refresh_token = True

    def create_authorization_code(self, client, grant_user, request):
        code = secrets.token_urlsafe(32)
        logger.debug(f"Generated authorization code '{code[:6]}...' for client '{client.client_id}'")
        auth_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.args.get('redirect_uri'),
            scope=request.args.get('scope'),
            nonce=request.args.get('nonce'),
            code_challenge=request.args.get('code_challenge'),
            code_challenge_method=request.args.get('code_challenge_method'),
            response_type=request.args.get('response_type', 'code'),
            state=request.args.get('state'),
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 600
        )
        database.session.add(auth_code)
        database.session.commit()
        logger.debug(f"Stored authorization code in database: {auth_code.code[:6]}...")
        return code

    def parse_authorization_code(self, code, client):
        logger.debug(f"Parsing authorization code '{code[:6]}...' for client '{client.client_id}'")
        auth_code = AuthorizationCode.query.filter_by(code=code, client_id=client.client_id).first()
        if not auth_code:
            logger.warning(f"Authorization code '{code[:6]}...' not found for client '{client.client_id}'")
            return None
        if time.time() > auth_code.expires_at:
            logger.warning(f"Authorization code '{code[:6]}...' has expired")
            database.session.delete(auth_code)
            database.session.commit()
            return None
        logger.debug(f"Parsed valid authorization code data for '{code[:6]}...': {auth_code.__dict__}")
        return auth_code

    def query_authorization_code(self, code, client):
        logger.debug(f"Querying authorization code '{code[:6]}...' for client '{client.client_id}'")
        auth_code = AuthorizationCode.query.filter_by(code=code, client_id=client.client_id).first()
        if not auth_code:
            logger.warning(f"Authorization code '{code[:6]}...' not found for client '{client_id}'")
            return None
        if time.time() > auth_code.expires_at:
            logger.warning(f"Authorization code '{code[:6]}...' has expired")
            database.session.delete(auth_code)
            database.session.commit()
            return None
        logger.debug(f"Queried valid authorization code data for '{code[:6]}...': {auth_code.__dict__}")
        return auth_code

    def delete_authorization_code(self, code):
        logger.debug(f"Deleting authorization code '{code[:6]}...'")
        auth_code = AuthorizationCode.query.filter_by(code=code).first()
        if auth_code:
            database.session.delete(auth_code)
            database.session.commit()
            logger.debug(f"Authorization code '{code[:6]}...' deleted from database")

    def authenticate_user(self, code_data):
        logger.debug("Returning dummy user for authorization code")
        return DummyUser()

    def validate_code_verifier(self, code_verifier, code_challenge, code_challenge_method):
        logger.debug(f"Validating PKCE code verifier. Code verifier: {code_verifier[:6]}..., Code challenge: {code_challenge[:6]}..., Method: {code_challenge_method}")
        if not code_verifier or not code_challenge:
            logger.warning("Missing code verifier or code challenge")
            return False
        if code_challenge_method == 'plain':
            expected_challenge = code_verifier
        elif code_challenge_method == 'S256':
            expected_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode('ascii')).digest()
            ).decode('ascii').rstrip('=')
        else:
            logger.warning(f"Unsupported code challenge method: {code_challenge_method}")
            return False
        is_valid = expected_challenge == code_challenge
        logger.debug(f"PKCE validation result: {is_valid}")
        return is_valid

    def create_token_response(self):
        self.validate_token_request()
        code = self.request.form.get('code')
        client = self.request.client
        grant_type = self.request.form.get('grant_type')
        if not code:
            raise OAuth2Error("invalid_request", "Missing 'code' parameter")
        if not grant_type:
            raise OAuth2Error("invalid_request", "Missing 'grant_type' parameter")
        code_data = self.query_authorization_code(code, client)
        if not code_data:
            raise OAuth2Error("invalid_grant", "Authorization code not found or expired")
        user = self.authenticate_user(code_data)
        if not user:
            raise OAuth2Error("invalid_grant", "No user for this code")
        scope = code_data.get_scope()
        token = self.generate_token(
            client,
            grant_type,
            user,
            scope,
            include_refresh_token=self.include_refresh_token,
            code=code
        )
        self.delete_authorization_code(code)
        body = {
            "access_token": token["access_token"],
            "token_type": token["token_type"],
            "expires_in": current_app.config['TOKEN_DURATION'],
            "scope": scope if scope else "",
            "refresh_token": token.get("refresh_token"),
        }
        headers = {"Content-Type": "application/json"}
        return 200, body, headers

    def generate_token(self, client, grant_type, user=None, scope=None, include_refresh_token=True, **kwargs):
        logger.debug(f"Generating token for client: {client.client_id}, grant_type: {grant_type}")
        code = kwargs.pop('code', None)
        token = {}
        token['access_token'] = secrets.token_urlsafe(32)
        token['token_type'] = 'Bearer'
        token['expires_in'] = current_app.config['TOKEN_DURATION']
        token['scope'] = scope if scope else ""
        token['issued_at'] = int(time.time())
        if include_refresh_token and client.check_grant_type('refresh_token'):
            token['refresh_token'] = secrets.token_urlsafe(32)
            token['refresh_token_expires_in'] = current_app.config['REFRESH_TOKEN_DURATION']
        if code:
            code_data = self.parse_authorization_code(code, client)
            if code_data and code_data.nonce:
                token['nonce'] = code_data.nonce
        logger.debug(f"Generated token for client '{client.client_id}'. Scope: {scope}")
        return token

def configure_oauth(flask_app, db=None, registered_app_model=None, oauth_token_model=None, auth_code_model=None):
    global database, RegisteredApp, OAuthToken, AuthorizationCode
    database = db or database
    RegisteredApp = registered_app_model or RegisteredApp
    OAuthToken = oauth_token_model or OAuthToken
    AuthorizationCode = auth_code_model or AuthorizationCode
    if not (database and RegisteredApp and OAuthToken and AuthorizationCode):
        raise ValueError("Database and models must be provided")
    authorization_server.init_app(
        flask_app,
        query_client=query_client,
        save_token=save_token
    )
    authorization_server.register_grant(AuthorizationCodeGrant)
    logger.info("Authlib OAuth2 server configured")

@smart_blueprint.route('/.well-known/smart-configuration', methods=['GET'])
@swag_from({
    'tags': ['OAuth2'],
    'summary': 'SMART on FHIR Configuration',
    'description': 'Returns the SMART on FHIR configuration.',
    'responses': {
        '200': {
            'description': 'SMART configuration',
            'schema': {
                'type': 'object',
                'properties': {
                    'issuer': {'type': 'string'},
                    'authorization_endpoint': {'type': 'string'},
                    'token_endpoint': {'type': 'string'},
                    'revocation_endpoint': {'type': 'string'},
                    'introspection_endpoint': {'type': 'string'},
                    'scopes_supported': {'type': 'array', 'items': {'type': 'string'}},
                    'response_types_supported': {'type': 'array', 'items': {'type': 'string'}},
                    'grant_types_supported': {'type': 'array', 'items': {'type': 'string'}},
                    'code_challenge_methods_supported': {'type': 'array', 'items': {'type': 'string'}}
                }
            }
        }
    }
})
def smart_configuration():
    config = {
        "issuer": request.url_root.rstrip('/'),
        "authorization_endpoint": url_for('smart_proxy.authorize', _external=True),
        "token_endpoint": url_for('smart_proxy.issue_token', _external=True),
        "revocation_endpoint": url_for('smart_proxy.revoke_token', _external=True),
        "introspection_endpoint": url_for('smart_proxy.introspect_token', _external=True),
        "scopes_supported": current_app.config['ALLOWED_SCOPES'].split(),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"]
    }
    return jsonify(config), 200

@smart_blueprint.route('/authorize', methods=['GET'])
@swag_from({
    'tags': ['OAuth2'],
    'summary': 'Initiate SMART on FHIR authorization',
    'description': 'Redirects to consent page, then to client redirect URI with code.',
    'parameters': [
        {'name': 'response_type', 'in': 'query', 'type': 'string', 'required': True, 'description': 'Must be "code".', 'enum': ['code']},
        {'name': 'client_id', 'in': 'query', 'type': 'string', 'required': True, 'description': 'Client ID.'},
        {'name': 'redirect_uri', 'in': 'query', 'type': 'string', 'required': True, 'description': 'Redirect URI.'},
        {'name': 'scope', 'in': 'query', 'type': 'string', 'required': True, 'description': 'Scopes.'},
        {'name': 'state', 'in': 'query', 'type': 'string', 'required': True, 'description': 'State.'},
        {'name': 'aud', 'in': 'query', 'type': 'string', 'required': True, 'description': 'FHIR server URL.'},
        {'name': 'code_challenge', 'in': 'query', 'type': 'string', 'required': False, 'description': 'PKCE challenge.'},
        {'name': 'code_challenge_method', 'in': 'query', 'type': 'string', 'required': False, 'description': 'PKCE method.', 'enum': ['plain', 'S256']}
    ],
    'responses': {
        '200': {'description': 'Consent page.'},
        '400': {'description': 'Invalid parameters.'}
    }
})
def authorize():
    try:
        logger.debug(f"Incoming request args: {request.args}")
        request_args = request.args.copy()
        request_args['scope'] = normalize_scopes(request_args.get('scope', ''))
        if 'aud' in request_args:
            del request_args['aud']
        request.args = request_args
        client = query_client(request_args.get('client_id'))
        if not client:
            return render_template('errors/auth_error.html', error="Invalid client_id"), 400
        response_type = request_args.get('response_type')
        if not response_type or not client.check_response_type(response_type):
            return render_template('errors/auth_error.html', error=f"Unsupported response_type: {response_type}"), 400
        redirect_uri = request_args.get('redirect_uri')
        if not redirect_uri or not client.check_redirect_uri(redirect_uri):
            return render_template('errors/auth_error.html', error=f"Invalid redirect_uri: {redirect_uri}"), 400
        requested_scopes = request_args.get('scope', '')
        allowed_scopes = client.get_allowed_scope(requested_scopes)
        if not allowed_scopes:
            return render_template('errors/auth_error.html', error=f"No valid scopes: {requested_scopes}"), 400
        request_args['scope'] = allowed_scopes
        request.args = request_args
        session['auth_request_params'] = request_args.to_dict()
        session['auth_client_id'] = client.client_id
        session['auth_scope'] = allowed_scopes
        session['auth_response_type'] = response_type
        session['auth_state'] = request_args.get('state')
        session['auth_nonce'] = request_args.get('nonce')
        return render_template(
            'auth/consent.html',
            client=client,
            scopes=session['auth_scope'].split(),
            request_params=session['auth_request_params'],
            form=ConsentForm()
        )
    except OAuth2Error as error:
        return render_template('errors/auth_error.html', error=f"{error.error}: {error.description}"), error.status_code
    except Exception as error:
        logger.error(f"Unexpected error during authorization: {error}", exc_info=True)
        return render_template('errors/auth_error.html', error="Unexpected error"), 500

@smart_blueprint.route('/consent', methods=['POST'])
def handle_consent():
    try:
        form = ConsentForm()
        # Manually validate form fields, bypassing CSRF
        if not form.is_submitted():
            return render_template('errors/auth_error.html', error="Form not submitted"), 400
        if not form.consent.data:
            return render_template('errors/auth_error.html', error="Consent value missing"), 400
        consent_granted = form.consent.data == 'allow'
        request_params = session.pop('auth_request_params', None)
        client_id = session.pop('auth_client_id', None)
        scope = session.pop('auth_scope', None)
        response_type = session.pop('auth_response_type', None)
        state = session.pop('auth_state', None)
        nonce = session.pop('auth_nonce', None)
        if not request_params or not client_id or not scope or not response_type:
            return render_template('errors/auth_error.html', error="Session expired or invalid"), 400
        client = query_client(client_id)
        if not client:
            return render_template('errors/auth_error.html', error="Invalid client_id"), 400
        if not client.check_response_type(response_type):
            return jsonify({"error": "unsupported_response_type"}), 400
        redirect_uri = request_params.get('redirect_uri')
        if not redirect_uri or not client.check_redirect_uri(redirect_uri):
            return render_template('errors/auth_error.html', error=f"Invalid redirect_uri: {redirect_uri}"), 400
        allowed_scopes = client.get_allowed_scope(scope)
        if not allowed_scopes:
            return render_template('errors/auth_error.html', error=f"No valid scopes: {scope}"), 400
        if consent_granted:
            request_args = request_params.copy()
            request_args['scope'] = allowed_scopes
            if state:
                request_args['state'] = state
            if nonce:
                request_args['nonce'] = nonce
            request.args = request_args
            request.form = {}
            request.method = 'GET'
            grant = AuthorizationCodeGrant(client, authorization_server)
            auth_code = grant.create_authorization_code(client, None, request)
            redirect_url = f"{redirect_uri}?code={auth_code}&state={state}" if state else f"{redirect_uri}?code={auth_code}"
            return redirect(redirect_url)
        else:
            redirect_url = f"{redirect_uri}?error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request"
            if state:
                redirect_url += f"&state={state}"
            return redirect(redirect_url)
    except OAuth2Error as error:
        return render_template('errors/auth_error.html', error=f"{error.error}: {error.description}"), error.status_code
    except Exception as error:
        logger.error(f"Unexpected error during consent handling: {error}", exc_info=True)
        return render_template('errors/auth_error.html', error="Unexpected error"), 500

@smart_blueprint.route('/token', methods=['POST'])
@swag_from({
    'tags': ['OAuth2'],
    'summary': 'Exchange code or refresh token for access token',
    'parameters': [
        {'name': 'grant_type', 'in': 'formData', 'type': 'string', 'required': True, 'enum': ['authorization_code', 'refresh_token']},
        {'name': 'code', 'in': 'formData', 'type': 'string', 'required': False},
        {'name': 'refresh_token', 'in': 'formData', 'type': 'string', 'required': False},
        {'name': 'redirect_uri', 'in': 'formData', 'type': 'string', 'required': False},
        {'name': 'client_id', 'in': 'formData', 'type': 'string', 'required': True},
        {'name': 'client_secret', 'in': 'formData', 'type': 'string', 'required': True},
        {'name': 'code_verifier', 'in': 'formData', 'type': 'string', 'required': False}
    ],
    'responses': {
        '200': {'description': 'Access token response'},
        '400': {'description': 'Invalid request'}
    }
})
def issue_token():
    try:
        response = authorization_server.create_token_response()
        if response.status_code == 200:
            token_data = response.get_json()
            logger.debug(f"Token issued: AccessToken={token_data.get('access_token')[:6]}...")
            return response
        else:
            error_data = response.get_json()
            logger.warning(f"Token request failed: {error_data.get('error')}")
            return jsonify(error_data), response.status_code
    except Exception as error:
        logger.error(f"Unexpected error during token issuance: {error}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": "Unexpected error"}), 500

@smart_blueprint.route('/revoke', methods=['POST'])
@swag_from({
    'tags': ['OAuth2'],
    'summary': 'Revoke an access or refresh token',
    'parameters': [
        {'name': 'token', 'in': 'formData', 'type': 'string', 'required': True},
        {'name': 'client_id', 'in': 'formData', 'type': 'string', 'required': True},
        {'name': 'client_secret', 'in': 'formData', 'type': 'string', 'required': True}
    ],
    'responses': {
        '200': {'description': 'Token revoked'},
        '400': {'description': 'Invalid request'}
    }
})
def revoke_token():
    try:
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        token = request.form.get('token')
        if not client_id or not client_secret or not token:
            return jsonify({"error": "invalid_request", "error_description": "Missing parameters"}), 400
        client = query_client(client_id)
        if not client or not client.check_client_secret(client_secret):
            return jsonify({"error": "invalid_client", "error_description": "Invalid client credentials"}), 400
        token_entry = OAuthToken.query.filter(
            (OAuthToken.access_token == token) | (OAuthToken.refresh_token == token)
        ).first()
        if token_entry:
            database.session.delete(token_entry)
            database.session.commit()
        return jsonify({"message": "Token revoked successfully."}), 200
    except Exception as error:
        logger.error(f"Unexpected error during token revocation: {error}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": "Unexpected error"}), 500

@smart_blueprint.route('/introspect', methods=['POST'])
@swag_from({
    'tags': ['OAuth2'],
    'summary': 'Introspect a token',
    'parameters': [
        {'name': 'token', 'in': 'formData', 'type': 'string', 'required': True},
        {'name': 'client_id', 'in': 'formData', 'type': 'string', 'required': True},
        {'name': 'client_secret', 'in': 'formData', 'type': 'string', 'required': True}
    ],
    'responses': {
        '200': {'description': 'Token introspection response'},
        '400': {'description': 'Invalid request'}
    }
})
def introspect_token():
    try:
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        token = request.form.get('token')
        if not client_id or not client_secret or not token:
            return jsonify({"error": "invalid_request", "error_description": "Missing parameters"}), 400
        client = query_client(client_id)
        if not client or not client.check_client_secret(client_secret):
            return jsonify({"error": "invalid_client", "error_description": "Invalid client credentials"}), 400
        token_entry = OAuthToken.query.filter(
            (OAuthToken.access_token == token) | (OAuthToken.refresh_token == token)
        ).first()
        if not token_entry:
            return jsonify({"active": False}), 200
        expires_at = token_entry.issued_at + token_entry.expires_in
        response = {
            "active": time.time() < expires_at,
            "client_id": token_entry.client_id,
            "scope": token_entry.scope or "",
            "exp": expires_at
        }
        return jsonify(response), 200
    except Exception as error:
        logger.error(f"Unexpected error during token introspection: {error}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": "Unexpected error"}), 500

@smart_blueprint.route('/proxy/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@require_oauth('launch launch/patient patient/*.read')
def proxy_fhir(path):
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({"error": "unauthorized", "error_description": "Missing Authorization header"}), 401
        token_entry = OAuthToken.query.filter_by(access_token=token).first()
        if not token_entry or time.time() > (token_entry.issued_at + token_entry.expires_in):
            return jsonify({"error": "unauthorized", "error_description": "Invalid or expired token"}), 401
        fhir_server_url = current_app.config['FHIR_SERVER_URL']
        target_url = f"{fhir_server_url.rstrip('/')}/{path}"
        headers = {k: v for k, v in request.headers.items() if not is_hop_by_hop_header(k)}
        headers['Authorization'] = f"Bearer {token}"
        response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            params=request.args,
            timeout=int(current_app.config['PROXY_TIMEOUT'])
        )
        return jsonify(response.json()), response.status_code, {
            k: v for k, v in response.headers.items() if not is_hop_by_hop_header(k)
        }
    except requests.RequestException as error:
        logger.error(f"Error proxying FHIR request: {error}", exc_info=True)
        return jsonify({"error": "proxy_error", "error_description": str(error)}), 502
    except Exception as error:
        logger.error(f"Unexpected error during FHIR proxy: {error}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": "Unexpected error"}), 500