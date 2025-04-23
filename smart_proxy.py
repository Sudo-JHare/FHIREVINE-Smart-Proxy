import time
import logging
import secrets
import requests
import base64
import hashlib
from flask import Blueprint, request, session, url_for, render_template, redirect, jsonify
from flasgger import swag_from
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
)
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6749.errors import OAuth2Error

# Import necessary components (designed for modularity)
try:
    from models import database, RegisteredApp, OAuthToken, AuthorizationCode
except ImportError:
    # Allow standalone usage or alternative model imports for FHIRFLARE integration
    database = None
    RegisteredApp = None
    OAuthToken = None
    AuthorizationCode = None

# Configure logging
logger = logging.getLogger(__name__)

# Define the Flask blueprint for SMART on FHIR routes
smart_blueprint = Blueprint('smart_proxy', __name__, template_folder='templates')

# Initialize Authlib AuthorizationServer and ResourceProtector globally
authorization_server = AuthorizationServer()
require_oauth = ResourceProtector()

# Helper functions for Authlib
def query_client(client_id):
    """Query client details from the database for Authlib."""
    logger.debug(f"Querying client with identifier: {client_id}")
    client = RegisteredApp.query.filter_by(client_id=client_id).first()
    if client:
        logger.debug(f"Found client: {client.app_name} (ClientID: {client.client_id})")
    else:
        logger.warning(f"Client not found for identifier: {client_id}")
    return client

def save_token(token, request):
    """Save generated OAuth2 tokens to the database."""
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
    """Convert plus signs or other delimiters to spaces for scopes."""
    if not scope_string:
        return ''
    return ' '.join(scope_string.replace('+', ' ').split())

# Dummy user class to satisfy Authlib's requirement
class DummyUser:
    def get_user_id(self):
        """Return a user ID for Authlib."""
        return "proxy_user"

# Custom Authorization Code Grant implementation
class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    """Customized Authorization Code Grant using database storage for codes."""
    
    SUPPORTED_RESPONSE_TYPES = ['code']  # Explicitly allow 'code'
    include_refresh_token = True  # Ensure refresh tokens are included
    TOKEN_DURATION = 3600  # Access token lifetime in seconds (1 hour)
    REFRESH_TOKEN_DURATION = 86400  # Refresh token lifetime in seconds (1 day)

    def create_authorization_code(self, client, grant_user, request):
        # Generate a secure random code
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
            expires_at=int(time.time()) + 600  # 10 minutes expiry
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
        """Query the authorization code from the database."""
        logger.debug(f"Querying authorization code '{code[:6]}...' for client '{client.client_id}'")
        auth_code = AuthorizationCode.query.filter_by(code=code, client_id=client.client_id).first()
        if not auth_code:
            logger.warning(f"Authorization code '{code[:6]}...' not found for client '{client.client_id}'")
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
        logger.debug("Returning dummy user for authorization code (no user authentication in this proxy)")
        return DummyUser()

    def validate_code_verifier(self, code_verifier, code_challenge, code_challenge_method):
        """Validate the PKCE code verifier against the stored code challenge."""
        logger.debug(f"Validating PKCE code verifier. Code verifier: {code_verifier[:6]}..., Code challenge: {code_challenge[:6]}..., Method: {code_challenge_method}")
        if not code_verifier or not code_challenge:
            logger.warning("Missing code verifier or code challenge for PKCE validation")
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
        logger.debug(f"PKCE validation result: {is_valid}. Expected challenge: {expected_challenge[:6]}..., Provided challenge: {code_challenge[:6]}...")
        return is_valid

    def create_token_response(self):
        """Override to ensure proper token generation with client and grant_type."""
        # Validate the token request (sets self.client, self.request, etc.)
        self.validate_token_request()
        
        # Get the authorization code from form data
        code = self.request.form.get('code')
        client = self.request.client
        grant_type = self.request.form.get('grant_type')
        
        if not code:
            raise OAuth2Error("invalid_request", "Missing 'code' parameter")
        
        if not grant_type:
            raise OAuth2Error("invalid_request", "Missing 'grant_type' parameter")
        
        # Authenticate user
        code_data = self.query_authorization_code(code, client)
        if not code_data:
            raise OAuth2Error("invalid_grant", "Authorization code not found or expired")
        
        user = self.authenticate_user(code_data)
        if not user:
            raise OAuth2Error("invalid_grant", "There is no 'user' for this code.")
        
        # Get the scope
        scope = code_data.get_scope()
        
        # Generate the token with custom expiration durations
        token = self.generate_token(
            client,
            grant_type,
            user,
            scope,
            include_refresh_token=self.include_refresh_token,
            code=code
        )
        
        # Delete the authorization code
        self.delete_authorization_code(code)
        
        # Ensure token has correct expires_in and scope
        body = {
            "access_token": token["access_token"],
            "token_type": token["token_type"],
            "expires_in": self.TOKEN_DURATION,  # Explicitly set to ensure correct value
            "scope": scope if scope else "",  # Use the scope directly
            "refresh_token": token.get("refresh_token"),
        }
        headers = {"Content-Type": "application/json"}
        return 200, body, headers

    def generate_token(self, client, grant_type, user=None, scope=None, include_refresh_token=True, **kwargs):
        """Generate an access token with optional nonce."""
        logger.debug(f"Generating token with client: {client.client_id}, grant_type: {grant_type}, user: {user.get_user_id() if user else None}, scope: {scope}")
        # Extract code from kwargs and remove it to avoid passing to parent
        code = kwargs.pop('code', None)
        
        # Prepare token parameters
        token = {}
        token['access_token'] = secrets.token_urlsafe(32)
        token['token_type'] = 'Bearer'
        token['expires_in'] = self.TOKEN_DURATION
        token['scope'] = scope if scope else ""
        token['issued_at'] = int(time.time())
        
        # Generate refresh token if enabled
        if include_refresh_token and client.check_grant_type('refresh_token'):
            token['refresh_token'] = secrets.token_urlsafe(32)
            # Set refresh token expiration (issued_at + duration)
            token['refresh_token_expires_in'] = self.REFRESH_TOKEN_DURATION
        
        # Handle nonce if code is provided
        if code:
            code_data = self.parse_authorization_code(code, client)
            if code_data:
                logger.info(f"Generating token. Nonce: {code_data.nonce}")
                if code_data.nonce:
                    token['nonce'] = code_data.nonce
            else:
                logger.warning(f"Could not retrieve code data for code '{code[:6]}...' during token generation")
        
        logger.debug(f"Generated token for client '{client.client_id}'. Scope: {scope}")
        return token

# Configure Authlib
def configure_oauth(flask_app, db=None, registered_app_model=None, oauth_token_model=None, auth_code_model=None):
    """Configure the Authlib AuthorizationServer with the Flask application."""
    global database, RegisteredApp, OAuthToken, AuthorizationCode
    # Allow dependency injection for FHIRFLARE integration
    database = db or database
    RegisteredApp = registered_app_model or RegisteredApp
    OAuthToken = oauth_token_model or OAuthToken
    AuthorizationCode = auth_code_model or AuthorizationCode

    if not (database and RegisteredApp and OAuthToken and AuthorizationCode):
        raise ValueError("Database and models must be provided for OAuth2 configuration")

    authorization_server.init_app(
        flask_app,
        query_client=query_client,
        save_token=save_token
    )
    authorization_server.register_grant(AuthorizationCodeGrant)
    logger.info("Authlib OAuth2 server configured successfully")

# SMART on FHIR OAuth2 routes
@smart_blueprint.route('/authorize', methods=['GET'])
@swag_from({
    'tags': ['OAuth2'],
    'summary': 'Initiate SMART on FHIR authorization',
    'description': 'Redirects to the consent page for user authorization, then redirects to the client redirect URI with an authorization code.',
    'parameters': [
        {
            'name': 'response_type',
            'in': 'query',
            'type': 'string',
            'required': True,
            'description': 'Must be "code" for authorization code flow.',
            'enum': ['code']
        },
        {
            'name': 'client_id',
            'in': 'query',
            'type': 'string',
            'required': True,
            'description': 'Client ID of the registered application.'
        },
        {
            'name': 'redirect_uri',
            'in': 'query',
            'type': 'string',
            'required': True,
            'description': 'Redirect URI where the authorization code will be sent.'
        },
        {
            'name': 'scope',
            'in': 'query',
            'type': 'string',
            'required': True,
            'description': 'Space-separated list of scopes (e.g., "openid launch/patient").'
        },
        {
            'name': 'state',
            'in': 'query',
            'type': 'string',
            'required': True,
            'description': 'Opaque value used to maintain state between the request and callback.'
        },
        {
            'name': 'aud',
            'in': 'query',
            'type': 'string',
            'required': True,
            'description': 'Audience URL of the FHIR server.'
        },
        {
            'name': 'code_challenge',
            'in': 'query',
            'type': 'string',
            'required': False,
            'description': 'PKCE code challenge (required for PKCE flow).'
        },
        {
            'name': 'code_challenge_method',
            'in': 'query',
            'type': 'string',
            'required': False,
            'description': 'PKCE code challenge method (default: "plain").',
            'enum': ['plain', 'S256']
        }
    ],
    'responses': {
        '200': {
            'description': 'Renders the consent page for user authorization.'
        },
        '400': {
            'description': 'Invalid request parameters (e.g., invalid client_id, redirect_uri, or scopes).'
        }
    }
})
def authorize():
    """Handle SMART on FHIR authorization requests."""
    try:
        # Log the incoming request parameters
        logger.debug(f"Incoming request args: {request.args}")

        # Normalize scopes in the request
        request_args = request.args.copy()
        request_args['scope'] = normalize_scopes(request_args.get('scope', ''))
        # Remove 'aud' as it's not needed for Authlib's OAuth flow
        if 'aud' in request_args:
            del request_args['aud']
        request.args = request_args
        logger.debug(f"Normalized request args: {request.args}")

        # Validate client
        client = query_client(request_args.get('client_id'))
        if not client:
            logger.error(f"Invalid client_id: {request_args.get('client_id')}")
            return render_template('errors/auth_error.html', error="Invalid client_id"), 400

        # Validate response_type
        response_type = request_args.get('response_type')
        logger.debug(f"Received response_type: {response_type}")
        if not response_type or not client.check_response_type(response_type):
            logger.error(f"Unsupported response_type: {response_type}")
            return render_template('errors/auth_error.html', error=f"Unsupported response_type: {response_type}"), 400

        # Validate redirect_uri
        redirect_uri = request_args.get('redirect_uri')
        if not redirect_uri or not client.check_redirect_uri(redirect_uri):
            logger.error(f"Invalid redirect_uri: {redirect_uri} (Registered URIs: {client.redirect_uris})")
            return render_template('errors/auth_error.html', error=f"Invalid redirect_uri: {redirect_uri}"), 400

        # Validate scopes
        requested_scopes = request_args.get('scope', '')
        allowed_scopes = client.get_allowed_scope(requested_scopes)
        if not allowed_scopes:
            logger.error(f"No valid scopes provided: {requested_scopes} (Allowed scopes: {client.scopes})")
            return render_template('errors/auth_error.html', error=f"No valid scopes provided: {requested_scopes}"), 400
        logger.debug(f"Allowed scopes after validation: {allowed_scopes}")

        # Update the request args with the normalized allowed scopes
        request_args['scope'] = allowed_scopes
        request.args = request_args
        logger.debug(f"Updated request args with normalized scopes: {request.args}")

        # Store request details in session for consent
        session['auth_request_params'] = request_args.to_dict()
        session['auth_client_id'] = client.client_id
        session['auth_scope'] = allowed_scopes
        session['auth_response_type'] = response_type
        session['auth_state'] = request_args.get('state')
        session['auth_nonce'] = request_args.get('nonce')

        # Render consent page
        logger.info(f"Rendering consent page for client: {client.app_name}")
        return render_template(
            'auth/consent.html',
            client=client,
            scopes=session['auth_scope'].split(),
            request_params=session['auth_request_params']
        )
    except OAuth2Error as error:
        logger.error(f"OAuth2 error during authorization: {error.error} - {error.description}", exc_info=True)
        return render_template('errors/auth_error.html', error=f"{error.error}: {error.description}"), error.status_code
    except Exception as error:
        logger.error(f"Unexpected error during authorization: {error}", exc_info=True)
        return render_template('errors/auth_error.html', error="An unexpected error occurred during authorization"), 500

@smart_blueprint.route('/consent', methods=['POST'])
def handle_consent():
    """Handle user consent submission for SMART on FHIR authorization."""
    try:
        # Log the entire form data for debugging
        logger.debug(f"Form data received: {request.form}")

        # Retrieve grant details from session
        request_params = session.pop('auth_request_params', None)
        client_id = session.pop('auth_client_id', None)
        scope = session.pop('auth_scope', None)
        response_type = session.pop('auth_response_type', None)
        state = session.pop('auth_state', None)
        nonce = session.pop('auth_nonce', None)

        logger.debug(f"Consent route: client_id={client_id}, scope={scope}, response_type={response_type}, state={state}, nonce={nonce}")

        if not request_params or not client_id or not scope or not response_type:
            logger.error("Consent handling failed: Missing session data")
            return render_template('errors/auth_error.html', error="Session expired or invalid"), 400

        # Validate client
        client = query_client(client_id)
        if not client:
            logger.error(f"Invalid client_id: {client_id}")
            return render_template('errors/auth_error.html', error="Invalid client_id"), 400

        # Validate response_type
        if not client.check_response_type(response_type):
            logger.error(f"Unsupported response_type: {response_type} for client '{client_id}'")
            return jsonify({"error": "unsupported_response_type"}), 400

        # Validate redirect_uri
        redirect_uri = request_params.get('redirect_uri')
        if not redirect_uri or not client.check_redirect_uri(redirect_uri):
            logger.error(f"Invalid redirect_uri in consent: {redirect_uri} (Registered URIs: {client.redirect_uris})")
            return render_template('errors/auth_error.html', error=f"Invalid redirect_uri: {redirect_uri}"), 400

        # Validate scopes
        allowed_scopes = client.get_allowed_scope(scope)
        if not allowed_scopes:
            logger.error(f"No valid scopes in consent: {scope} (Allowed scopes: {client.scopes})")
            return render_template('errors/auth_error.html', error=f"No valid scopes: {scope}"), 400
        logger.debug(f"Allowed scopes after validation in consent: {allowed_scopes}")

        consent_granted = request.form.get('consent') == 'allow'
        logger.debug(f"Consent granted: {consent_granted}")

        if consent_granted:
            logger.info(f"Consent granted for client '{client_id}' with scope '{scope}'")
            # Reconstruct request for Authlib
            request_args = request_params.copy()
            request_args['scope'] = allowed_scopes  # Use validated scopes in normalized order
            if state:
                request_args['state'] = state
            if nonce:
                request_args['nonce'] = nonce
            request.args = request_args
            request.form = {}  # Ensure form is empty for GET-like request
            request.method = 'GET'  # Match /authorize
            logger.debug(f"Reconstructed request args for token generation: {request.args}")

            # Access AuthorizationCodeGrant instance to generate the code
            grant = AuthorizationCodeGrant(client, authorization_server)
            auth_code = grant.create_authorization_code(client, None, request)
            redirect_url = f"{redirect_uri}?code={auth_code}&state={state}" if state else f"{redirect_uri}?code={auth_code}"
            logger.debug(f"Redirecting to: {redirect_url}")
            return redirect(redirect_url)
        else:
            logger.info(f"Consent denied for client '{client_id}'")
            redirect_url = f"{redirect_uri}?error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request"
            if state:
                redirect_url += f"&state={state}"
            logger.debug(f"Redirecting to: {redirect_url}")
            return redirect(redirect_url)
    except OAuth2Error as error:
        logger.error(f"OAuth2 error during consent handling: {error.error} - {error.description}", exc_info=True)
        return render_template('errors/auth_error.html', error=f"{error.error}: {error.description}"), error.status_code
    except Exception as error:
        logger.error(f"Unexpected error during consent handling: {error}", exc_info=True)
        return render_template('errors/auth_error.html', error="An unexpected error occurred during consent handling"), 500

@smart_blueprint.route('/token', methods=['POST'])
@swag_from({
    'tags': ['OAuth2'],
    'summary': 'Exchange authorization code or refresh token for access token',
    'description': 'Exchanges an authorization code or refresh token for an access token and refresh token.',
    'parameters': [
        {
            'name': 'grant_type',
            'in': 'formData',
            'type': 'string',
            'required': True,
            'description': 'Type of grant ("authorization_code" or "refresh_token").',
            'enum': ['authorization_code', 'refresh_token']
        },
        {
            'name': 'code',
            'in': 'formData',
            'type': 'string',
            'required': False,
            'description': 'Authorization code received from /authorize (required for grant_type=authorization_code).'
        },
        {
            'name': 'refresh_token',
            'in': 'formData',
            'type': 'string',
            'required': False,
            'description': 'Refresh token to obtain a new access token (required for grant_type=refresh_token).'
        },
        {
            'name': 'redirect_uri',
            'in': 'formData',
            'type': 'string',
            'required': False,
            'description': 'The redirect URI used in the authorization request (required for grant_type=authorization_code).'
        },
        {
            'name': 'client_id',
            'in': 'formData',
            'type': 'string',
            'required': True,
            'description': 'Client ID of the registered application.'
        },
        {
            'name': 'client_secret',
            'in': 'formData',
            'type': 'string',
            'required': True,
            'description': 'Client secret of the registered application.'
        },
        {
            'name': 'code_verifier',
            'in': 'formData',
            'type': 'string',
            'required': False,
            'description': 'PKCE code verifier (required if code_challenge was used in /authorize).'
        }
    ],
    'responses': {
        '200': {
            'description': 'Access token response',
            'schema': {
                'type': 'object',
                'properties': {
                    'access_token': {'type': 'string'},
                    'token_type': {'type': 'string', 'example': 'Bearer'},
                    'expires_in': {'type': 'integer', 'example': 3600},
                    'scope': {'type': 'string'},
                    'refresh_token': {'type': 'string'}
                }
            }
        },
        '400': {
            'description': 'Invalid request (e.g., invalid code, refresh token, client credentials, redirect_uri, or code_verifier).'
        }
    }
})
def issue_token():
    """Issue SMART on FHIR access tokens."""
    try:
        logger.info("Token endpoint called")
        # Log the incoming request parameters
        logger.debug(f"Request form data: {request.form}")
        logger.debug(f"Request headers: {dict(request.headers)}")
        response = authorization_server.create_token_response()
        logger.info(f"Token response created. Status code: {response.status_code}")

        if response.status_code == 200:
            try:
                token_data = response.get_json()
                logger.debug(f"Token issued: AccessToken={token_data.get('access_token')[:6]}..., Type={token_data.get('token_type')}, Scope={token_data.get('scope')}, ExpiresIn={token_data.get('expires_in')}, RefreshToken={token_data.get('refresh_token')[:6] if token_data.get('refresh_token') else None}...")
                return response
            except Exception:
                logger.warning("Could not parse token response JSON for logging")
                return response
        else:
            try:
                error_data = response.get_json()
                logger.warning(f"Token request failed: Error={error_data.get('error')}, Description={error_data.get('error_description')}")
                return jsonify(error_data), response.status_code
            except Exception:
                logger.warning(f"Token request failed with status {response.status_code}. Could not parse error response")
                return jsonify({"error": "invalid_request", "error_description": "Failed to process token request"}), response.status_code
    except Exception as error:
        logger.error(f"Unexpected error during token issuance: {error}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": "An unexpected error occurred during token issuance"}), 500

@smart_blueprint.route('/revoke', methods=['POST'])
@swag_from({
    'tags': ['OAuth2'],
    'summary': 'Revoke an access or refresh token',
    'description': 'Revokes an access or refresh token, rendering it invalid for future use.',
    'parameters': [
        {
            'name': 'token',
            'in': 'formData',
            'type': 'string',
            'required': True,
            'description': 'The access or refresh token to revoke.'
        },
        {
            'name': 'client_id',
            'in': 'formData',
            'type': 'string',
            'required': True,
            'description': 'Client ID of the registered application.'
        },
        {
            'name': 'client_secret',
            'in': 'formData',
            'type': 'string',
            'required': True,
            'description': 'Client secret of the registered application.'
        }
    ],
    'responses': {
        '200': {
            'description': 'Token revoked successfully.',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string', 'example': 'Token revoked successfully.'}
                }
            }
        },
        '400': {
            'description': 'Invalid request (e.g., invalid client credentials or token).'
        }
    }
})
def revoke_token():
    """Revoke an access or refresh token."""
    try:
        logger.info("Token revocation endpoint called")
        # Log the incoming request parameters
        logger.debug(f"Request form data: {request.form}")
        logger.debug(f"Request headers: {dict(request.headers)}")

        # Validate client credentials
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        token = request.form.get('token')

        if not client_id or not client_secret or not token:
            logger.warning("Missing required parameters in token revocation request")
            return jsonify({"error": "invalid_request", "error_description": "Missing required parameters"}), 400

        client = query_client(client_id)
        if not client:
            logger.warning(f"Invalid client_id: {client_id}")
            return jsonify({"error": "invalid_client", "error_description": "Invalid client_id"}), 400

        if not client.check_client_secret(client_secret):
            logger.warning(f"Invalid client_secret for client '{client_id}'")
            return jsonify({"error": "invalid_client", "error_description": "Invalid client_secret"}), 400

        # Revoke the token (delete it from the database)
        # Check if the token is an access token or refresh token
        token_entry = OAuthToken.query.filter(
            (OAuthToken.access_token == token) | (OAuthToken.refresh_token == token)
        ).first()

        if token_entry:
            database.session.delete(token_entry)
            database.session.commit()
            logger.info(f"Token revoked successfully for client '{client_id}'")
            return jsonify({"message": "Token revoked successfully."}), 200
        else:
            logger.warning(f"Token not found: {token[:6]}...")
            # RFC 7009 states that revocation endpoints should return 200 even if the token is not found
            return jsonify({"message": "Token revoked successfully."}), 200

    except Exception as error:
        logger.error(f"Unexpected error during token revocation: {error}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": "An unexpected error occurred during token revocation"}), 500