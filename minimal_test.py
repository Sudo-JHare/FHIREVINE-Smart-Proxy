# minimal_test.py (Updated to Run Test)
import logging
import os
from flask import Flask, request, jsonify
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749.errors import OAuth2Error
from werkzeug.datastructures import ImmutableMultiDict

# --- Basic Logging Setup ---
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(name)s:%(message)s') # Simplified format for clarity
logger = logging.getLogger(__name__)

# --- Dummy Client Implementation ---
class DummyClient:
    def __init__(self, client_id, redirect_uris, scopes, response_types=['code']):
        self.client_id = client_id
        self._redirect_uris = redirect_uris.split() if isinstance(redirect_uris, str) else redirect_uris
        self._scopes = scopes.split() if isinstance(scopes, str) else scopes
        self._response_types = response_types

    def get_client_id(self):
        return self.client_id

    def check_redirect_uri(self, redirect_uri):
        logger.debug(f"[DummyClient] Checking redirect_uri: '{redirect_uri}' against {self._redirect_uris}")
        return redirect_uri in self._redirect_uris

    def check_response_type(self, response_type):
        logger.debug(f"[DummyClient] Checking response_type: '{response_type}' against {self._response_types}")
        return response_type in self._response_types

    def get_allowed_scopes(self, requested_scopes):
         allowed = set(self._scopes)
         requested = set(requested_scopes.split())
         granted = allowed.intersection(requested)
         logger.debug(f"[DummyClient] Checking scopes: Requested={requested}, Allowed={allowed}, Granted={granted}")
         return ' '.join(list(granted))

    def check_grant_type(self, grant_type):
        return grant_type == 'authorization_code'

    def has_client_secret(self):
        return True

    def check_client_secret(self, client_secret):
        return True

# --- Dummy Query Client Function ---
DUMMY_CLIENT_ID = 'test-client-123'
DUMMY_REDIRECT_URI = 'http://localhost:8000/callback'
DUMMY_SCOPES = 'openid profile launch/patient patient/*.read'

dummy_client_instance = DummyClient(DUMMY_CLIENT_ID, DUMMY_REDIRECT_URI, DUMMY_SCOPES)

def query_client(client_id):
    logger.debug(f"[Minimal Test] query_client called for ID: {client_id}")
    if client_id == DUMMY_CLIENT_ID:
        logger.debug("[Minimal Test] Returning dummy client instance.")
        return dummy_client_instance
    logger.warning(f"[Minimal Test] Client ID '{client_id}' not found.")
    return None

# --- Flask App and Authlib Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'minimal-test-secret'

# Check Authlib version
try:
    import authlib
    import inspect
    logger.info(f"Authlib version found: {authlib.__version__}")
    logger.info(f"Authlib location: {inspect.getfile(authlib)}")
except ImportError:
    logger.error("Could not import Authlib!")
except Exception as e:
    logger.error(f"Error getting Authlib info: {e}")

# Initialize AuthorizationServer
authorization_server = AuthorizationServer(query_client=query_client)
authorization_server.init_app(app)

# --- Test Route ---
@app.route('/test-authlib')
def test_authlib_route():
    logger.info("--- Entered /test-authlib route ---")
    # NOTE: We are already inside a request context when run via test_client
    logger.info(f"Actual request URL: {request.url}")
    logger.info(f"Actual request Args: {request.args}")
    logger.debug(f"Attempting validation. Type of authorization_server: {type(authorization_server)}")
    try:
        # --- The critical call ---
        # Authlib uses the current request context (request.args, etc.)
        grant = authorization_server.validate_authorization_request()
        # ------------------------

        logger.info(">>> SUCCESS: validate_authorization_request() completed.")
        logger.info(f"Grant type: {type(grant)}")
        logger.info(f"Grant client: {grant.client.get_client_id() if grant and grant.client else 'N/A'}")
        return jsonify(status="success", message="validate_authorization_request() worked!", grant_type=str(type(grant)))

    except AttributeError as ae:
        logger.critical(f">>> FAILURE: AttributeError calling validate_authorization_request(): {ae}", exc_info=True)
        return jsonify(status="error", message=f"AttributeError: {ae}"), 500
    except OAuth2Error as error:
        logger.error(f">>> FAILURE: OAuth2Error calling validate_authorization_request(): {error.error} - {error.description}", exc_info=True)
        return jsonify(status="error", message=f"OAuth2Error: {error.error} - {error.description}"), 400
    except Exception as e:
        logger.error(f">>> FAILURE: Unexpected Exception calling validate_authorization_request(): {e}", exc_info=True)
        return jsonify(status="error", message=f"Unexpected Exception: {e}"), 500

# --- Function to Run the Test ---
def run_test():
    """Uses Flask's test client to execute the test route."""
    logger.info("--- Starting Test Run ---")
    client = app.test_client()
    # Construct the query parameters for the test request
    query_params = {
        'response_type': 'code',
        'client_id': DUMMY_CLIENT_ID,
        'redirect_uri': DUMMY_REDIRECT_URI,
        'scope': DUMMY_SCOPES,
        'state': 'dummy_state'
    }
    # Make a GET request to the test route
    response = client.get('/test-authlib', query_string=query_params)
    logger.info(f"--- Test Run Complete --- Status Code: {response.status_code} ---")
    # Print the JSON response body for verification
    try:
        logger.info(f"Response JSON: {response.get_json()}")
    except Exception:
        logger.info(f"Response Data: {response.data.decode()}")


# --- Main execution block ---
if __name__ == '__main__':
    logger.info("Minimal test script loaded.")
    # Run the test function directly
    run_test()
