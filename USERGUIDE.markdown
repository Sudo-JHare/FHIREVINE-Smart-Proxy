# FHIRVINE SMART Proxy User Guide

## Introduction

FHIRVINE is a SMART on FHIR proxy that simplifies the integration, testing, and configuration of SMART applications with FHIR servers. This guide provides a comprehensive overview of all features, API endpoints, and use cases to help developers and administrators effectively use FHIRVINE.

## Features Overview

### App Gallery
- **Purpose**: Register, view, edit, and delete SMART applications.
- **Access**: Navigate to `/app-gallery` from the homepage.
- **Functionality**:
  - Register new apps with details like name, redirect URIs, scopes, and logo.
  - Edit existing app details.
  - Delete apps and associated tokens.
  - Test apps using temporary registrations (24-hour expiry).

### Test Client Mode
- **Purpose**: Simulate a SMART app client to test OAuth2 authentication flows.
- **Access**: Navigate to `/test-client`.
- **Functionality**:
  - Select a registered app by Client ID.
  - Choose response mode: inline (display response on page) or redirect (send to app’s redirect URI).
  - Initiate an OAuth2 authorization flow, grant consent, and view the resulting authorization code or token.

### Test Server Mode
- **Purpose**: Simulate a SMART on FHIR server to test app interactions.
- **Access**: Navigate to `/test-server`.
- **Functionality**:
  - Input Client ID, Client Secret, Redirect URI, and scopes.
  - Initiate an OAuth2 flow, grant consent, and receive an access token and refresh token.
  - View token details and test token exchange.

### Configuration Menu
- **Purpose**: Customize FHIRVINE’s behavior through a user-friendly interface.
- **Access**: Navigate to `/configure/security`, `/configure/proxy-settings`, or `/configure/server-endpoints`.
- **Submenus**:
  - **Security Settings**:
    - Configure access token duration (seconds).
    - Configure refresh token duration (seconds).
    - Set allowed OAuth2 scopes.
  - **Proxy Settings**:
    - Set the upstream FHIR server URL.
    - Adjust the proxy request timeout (seconds).
  - **Server Endpoints**:
    - Define the metadata endpoint path.
    - Define the capability statement endpoint path.
    - Define the base resource endpoint path.

### API Documentation
- **Purpose**: Explore and test FHIRVINE’s API endpoints.
- **Access**: Navigate to `/apidocs`.
- **Functionality**:
  - View all available API endpoints with descriptions.
  - Test endpoints directly from the Swagger UI.

## Web Interface Usage

### Homepage
- **URL**: `/`
- **Description**: The landing page provides an overview of FHIRVINE and navigation links to key features.
- **Actions**:
  - Click "Explore Apps" to access the App Gallery.
  - Click "Test Client" to test as a client.
  - Click "Test Server" to test as a server.
  - Click "Configure" to access the configuration menu.

### Registering a New App
1. Go to `/app-gallery`.
2. Click "Register New App".
3. Fill in the form:
   - **Application Name**: e.g., "My SMART App".
   - **Redirect URIs**: Space-separated list (e.g., `https://myapp.com/callback`).
   - **Allowed Scopes**: Space-separated (e.g., `patient/*.read openid`).
   - **Logo URI**, **Contacts**, **Terms of Service URI**, **Privacy Policy URI**: Optional fields.
4. Submit the form to receive a Client ID and Client Secret.

### Testing an App as a Client
1. Go to `/test-client`.
2. Select a Client ID from the dropdown (populated from registered apps).
3. Choose a response mode:
   - **Inline**: View the response on the page.
   - **Redirect**: Redirect to the app’s URI with the authorization code.
4. Click "Launch Test" to initiate the OAuth2 flow.
5. On the consent page (`/oauth2/authorize`), click "Allow" to proceed.
6. View the authorization code or token response.

### Testing as a Server
1. Go to `/test-server`.
2. Enter:
   - **Client ID**: From a registered app.
   - **Client Secret**: From registration.
   - **Redirect URI**: App’s callback URL.
   - **Scopes**: Space-separated scopes to request.
3. Click "Initiate Authorization".
4. Grant consent on the `/oauth2/authorize` page.
5. Receive and view the access token, refresh token, and token request details.

### Configuring Settings
- **Security Settings** (`/configure/security`):
  - Adjust token durations and scopes, then save.
- **Proxy Settings** (`/configure/proxy-settings`):
  - Set the FHIR server URL and timeout, then save.
- **Server Endpoints** (`/configure/server-endpoints`):
  - Define endpoint paths, then save.

## API Endpoints

### Overview
FHIRVINE exposes several API endpoints under the `/oauth2` prefix, documented via Swagger UI at `/apidocs`. Below are the key endpoints and their use cases.

### 1. Well-Known SMART Configuration
- **Endpoint**: `GET /.well-known/smart-configuration`
- **Description**: Provides the SMART on FHIR configuration for discovery.
- **Use Case**: Apps use this to discover FHIRVINE’s OAuth2 endpoints.
- **Response**:
  ```json
  {
    "issuer": "http://localhost:5001/oauth2",
    "authorization_endpoint": "http://localhost:5001/oauth2/authorize",
    "token_endpoint": "http://localhost:5001/oauth2/token",
    "revocation_endpoint": "http://localhost:5001/oauth2/revoke",
    "introspection_endpoint": "http://localhost:5001/oauth2/introspect",
    "scopes_supported": ["openid", "profile", "launch", "launch/patient", "patient/*.read", "offline_access"],
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token"]
  }
  ```

### 2. Authorize
- **Endpoint**: `GET /oauth2/authorize`
- **Description**: Initiates the OAuth2 authorization flow.
- **Parameters**:
  - `client_id`: Client ID of the app.
  - `redirect_uri`: App’s callback URL.
  - `scope`: Space-separated scopes (e.g., `patient/*.read openid`).
  - `response_type`: Must be `code`.
  - `state`: State parameter for CSRF protection.
  - `aud`: Audience (FHIR server URL).
  - `code_challenge`: PKCE code challenge.
  - `code_challenge_method`: Must be `S256`.
- **Use Case**: Redirect users to authenticate and authorize the app.
- **Response**: Redirects to the `redirect_uri` with an authorization code (e.g., `?code=<code>&state=<state>`).

### 3. Token
- **Endpoint**: `POST /oauth2/token`
- **Description**: Exchanges an authorization code for an access token.
- **Parameters**:
  - `grant_type`: `authorization_code` or `refresh_token`.
  - `code`: Authorization code (for `authorization_code` grant).
  - `redirect_uri`: Must match the original redirect URI.
  - `client_id`: Client ID.
  - `client_secret`: Client Secret.
  - `code_verifier`: PKCE code verifier.
  - `refresh_token`: Refresh token (for `refresh_token` grant).
- **Use Case**: Obtain access and refresh tokens to interact with the FHIR server.
- **Response**:
  ```json
  {
    "access_token": "<access-token>",
    "refresh_token": "<refresh-token>",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "patient/*.read openid"
  }
  ```

### 4. Revoke
- **Endpoint**: `POST /oauth2/revoke`
- **Description**: Revokes an access or refresh token.
- **Parameters**:
  - `token`: The token to revoke.
  - `token_type_hint`: `access_token` or `refresh_token` (optional).
- **Use Case**: Invalidate tokens when they are no longer needed.
- **Response**:
  ```json
  {}
  ```

### 5. Introspect
- **Endpoint**: `POST /oauth2/introspect`
- **Description**: Verifies the status of a token.
- **Parameters**:
  - `token`: The token to introspect.
- **Use Case**: Check if a token is active or expired.
- **Response**:
  ```json
  {
    "active": true,
    "client_id": "<client-id>",
    "scope": "patient/*.read openid",
    "exp": 1698777600
  }
  ```

### 6. FHIR Proxy
- **Endpoint**: `GET|POST /oauth2/proxy/<path:path>`
- **Description**: Proxies requests to the upstream FHIR server, adding the access token in the Authorization header.
- **Parameters**:
  - `path`: The FHIR resource path (e.g., `Patient/123`).
  - Headers: `Authorization: Bearer <access-token>`.
- **Use Case**: Access FHIR resources securely through the proxy.
- **Response**: The FHIR server’s response (e.g., a Patient resource in JSON).

## Use Cases

### Use Case 1: Registering and Testing a SMART App
1. Register a new app in the App Gallery with redirect URI `https://myapp.com/callback` and scopes `patient/*.read openid`.
2. Use the Client ID and Secret in `/test-client` to simulate an OAuth2 flow.
3. Grant consent and receive an authorization code.
4. Exchange the code for an access token using the `/oauth2/token` endpoint.
5. Use the access token to query FHIR resources via `/oauth2/proxy/Patient`.

### Use Case 2: Configuring Proxy Settings
1. Go to `/configure/proxy-settings`.
2. Change the FHIR server URL to a custom server (e.g., `https://myfhirserver.com`).
3. Set the proxy timeout to 30 seconds.
4. Save the settings and test the proxy by querying a resource.

### Use Case 3: Revoking a Token
1. After testing an app, obtain a refresh token.
2. Use the `/oauth2/revoke` endpoint to invalidate the refresh token.
3. Verify the token’s status using `/oauth2/introspect`.

## Troubleshooting

### Common Issues
- **Configuration Values Not Displaying**:
  - Check the logs for `get_config_value` debug messages to confirm database retrieval.
  - Ensure the database (`/app/instance/fhirvine.db`) contains the correct values.
- **OAuth2 Flow Fails**:
  - Verify the Client ID, Secret, and Redirect URI match the registered app.
  - Check the FHIR server URL in `/configure/proxy-settings`.
- **Images Not Displaying**:
  - Ensure `FHIRVINE.png` is in `/app/static/`.
  - Check volume mounts in `docker-compose.yml` (e.g., `./static:/app/static`).

### Logs
- Logs are available via Docker:
  ```bash
  docker logs fhirvine_app
  ```
- Look for `DEBUG` and `ERROR` messages to diagnose issues.

## Support

For additional help, contact `support@fhirvine.example.com` or open an issue on the project’s GitHub repository.