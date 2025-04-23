# Integrating FHIRVINE with FHIRFLARE

## Overview

FHIRVINE can be integrated with FHIRFLARE (a Flask-based FHIR Implementation Guide toolkit) as a SMART on FHIR proxy module. This guide explains how to set up and integrate FHIRVINE with FHIRFLARE for seamless FHIR data access and validation.

## Prerequisites

- FHIRVINE and FHIRFLARE repositories cloned.
- Docker and Docker Compose installed.
- Both applications configured and running.

## Setup

### 1. Deploy FHIRVINE

Follow the FHIRVINE proxy setup guide (see `README_PROXY.md`). Ensure it’s running at `http://localhost:5001`.

### 2. Configure FHIRFLARE

- Clone FHIRFLARE:

  ```bash
  git clone https://github.com/Sudo-JHare/FHIRFLARE-IG-Toolkit
  cd FHIRFLARE-IG-Toolkit
  ```

- Update `appsettings.json` or environment variables to point to FHIRVINE’s proxy:

  ```json
  {
    "FhirServerUrl": "http://localhost:5001/oauth2/proxy",
    "AuthServerUrl": "http://localhost:5001/oauth2"
  }
  ```

### 3. Register FHIRFLARE as a SMART App in FHIRVINE

- In FHIRVINE, go to `http://localhost:5001/app-gallery`.
- Register FHIRFLARE as a new app:
  - Redirect URI: `http://localhost:8080/callback` (or FHIRFLARE’s callback URL).
  - Scopes: `patient/*.read offline_access`.
- Note the Client ID and Secret.

### 4. Update FHIRVINE Configuration

- In FHIRVINE, go to `http://localhost:5001/configure/proxy-settings`.
- Set the upstream FHIR server to FHIRFLARE’s target FHIR server (e.g., `http://hapi.fhir.org/baseR4`).

## Integration Steps

### 1. Authenticate FHIRFLARE via FHIRVINE

- In FHIRFLARE, initiate an OAuth2 flow using FHIRVINE’s `/oauth2/authorize` endpoint.
- Use the Client ID and Secret from FHIRVINE.
- After authorization, FHIRFLARE will receive an access token.

### 2. Access FHIR Data

- FHIRFLARE can now make FHIR requests through FHIRVINE’s proxy (e.g., `http://localhost:5001/oauth2/proxy/Patient`).
- The proxy will handle authentication and forward requests to the upstream FHIR server.

### 3. Validate FHIR Resources

- Use FHIRFLARE’s validation module to validate resources fetched via FHIRVINE’s proxy.
- Example: Fetch a Patient resource and validate it against an IG in FHIRFLARE.

## Troubleshooting

- **Auth Errors**: Ensure FHIRFLARE’s redirect URI matches the registered URI in FHIRVINE.
- **Proxy Errors**: Check FHIRVINE logs (`docker logs fhirvine_app`) and verify the upstream FHIR server URL.
- **Validation Issues**: Ensure FHIRFLARE’s IG package is correctly loaded.