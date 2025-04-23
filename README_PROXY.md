# Using and Setting Up the SMART on FHIR Proxy in FHIRVINE

## Overview

FHIRVINE provides a SMART on FHIR proxy to securely connect SMART apps to FHIR servers, supporting OAuth2 authentication and proxying requests. This guide explains how to set up and use the proxy function.

## Prerequisites

- Docker and Docker Compose installed.
- A FHIR server (e.g., `http://hapi.fhir.org/baseR4`).
- Python 3.11 (if running locally).

## Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd FHIRVINE
```

### 2. Configure Environment Variables

Copy the `.env.example` to `.env` and update the values:

```env
FLASK_ENV=development
SECRET_KEY=your-secure-random-key
DATABASE_URL=sqlite:////app/instance/fhirvine.db
FHIR_SERVER_URL=http://hapi.fhir.org/baseR4
```

### 3. Run with Docker

Build and start the application:

```bash
docker-compose up -d --build
```

The proxy will be available at `http://localhost:5001`.

### 4. (Optional) Run Locally

If not using Docker:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
flask db upgrade
flask run --host=0.0.0.0 --port=5001
```

## Using the Proxy

### 1. Register a SMART App

- Navigate to `http://localhost:5001/app-gallery`.
- Click "Register New App".
- Fill in details (e.g., Redirect URIs, Scopes) and submit to get a Client ID and Secret.

### 2. Test the Proxy

- Go to `http://localhost:5001/test-client`.
- Select your app’s Client ID, choose a response mode, and launch the test.
- Grant consent at `/oauth2/authorize`.
- The proxy will handle the OAuth2 flow and proxy FHIR requests to the upstream server (e.g., `/oauth2/proxy/Patient`).

### 3. Configure the Proxy

- Visit `http://localhost:5001/configure/proxy-settings` to set the FHIR server URL and proxy timeout.
- Save your settings to update the proxy configuration.

## Key Endpoints

- **Authorization**: `/oauth2/authorize` - Initiates the OAuth2 flow.
- **Token**: `/oauth2/token` - Exchanges code for an access token.
- **Proxy**: `/oauth2/proxy/<path>` - Proxies FHIR requests with the access token.

## Troubleshooting

- **Logs**: Check logs with `docker logs fhirvine_app` for errors.
- **Database**: Ensure values are saved in `/app/instance/fhirvine.db`.