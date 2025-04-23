# FHIRVINE SMART Proxy

## Overview

FHIRVINE is a lightweight, performant SMART on FHIR proxy built with Flask, designed to facilitate seamless integration and testing of SMART on FHIR applications. It acts as an intermediary between SMART apps and FHIR servers, providing OAuth2 authentication, app registration, testing capabilities, and configuration options. Key features include:

- **OAuth2 Authentication**: Supports SMART on FHIR OAuth2 flows for secure app authentication.
- **App Gallery**: Register, manage, and test SMART applications.
- **Testing Support**: Test client and server modes for simulating OAuth2 flows.
- **Configuration Menu**: Customize security settings, proxy settings, and server endpoints.
- **Modular Integration**: Designed to integrate with FHIRFLARE for extended functionality.
- **API Documentation**: Swagger UI for exploring available endpoints.

FHIRVINE is ideal for developers building and testing SMART on FHIR applications, ensuring compliance with FHIR standards while providing a user-friendly interface for configuration and testing.

## Prerequisites

- **Docker**: Required for containerized deployment.
- **Python 3.11**: If running locally without Docker.
- **Dependencies**: Listed in `requirements.txt` (e.g., Flask, Flask-SQLAlchemy, Authlib, Flasgger).

## Installation

### Using Docker (Recommended)

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd FHIRVINE
   ```

2. **Set Up Environment Variables**:
   - Copy the `.env.example` to `.env`:
     ```bash
     cp .env.example .env
     ```
   - Edit `.env` with your settings:
     ```
     FLASK_ENV=development
     SECRET_KEY=your-secure-random-key
     DATABASE_URL=sqlite:////app/instance/fhirvine.db
     FHIR_SERVER_URL=http://hapi.fhir.org/baseR4
     ```

3. **Build and Run with Docker Compose**:
   ```bash
   docker-compose up -d --build
   ```
   - The application will be available at `http://localhost:5001`.

4. **Access the Application**:
   - Open your browser and navigate to `http://localhost:5001`.

### Local Installation

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd FHIRVINE
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set Up Environment Variables**:
   - Follow the same steps as above to create and edit the `.env` file.

5. **Run Database Migrations**:
   ```bash
   flask db upgrade
   ```

6. **Start the Application**:
   ```bash
   flask run --host=0.0.0.0 --port=5001
   ```
   - Access the application at `http://localhost:5001`.

## Usage

FHIRVINE provides a web interface and API endpoints for managing SMART on FHIR applications. Key functionalities include:

- **App Gallery**: Register and manage SMART apps.
- **Test Client/Server**: Simulate OAuth2 flows for testing.
- **Configuration**: Adjust security, proxy, and server settings.
- **API Access**: Use the Swagger UI at `/apidocs` to explore endpoints.

For detailed usage instructions, including all features, API endpoints, and use cases, refer to the [User Guide](USERGUIDE.md).

## Project Structure

- `app.py`: Main Flask application file.
- `models.py`: SQLAlchemy models for database tables.
- `smart_proxy.py`: SMART on FHIR proxy logic and OAuth2 handling.
- `forms.py`: WTForms for handling form data.
- `templates/`: HTML templates for the web UI.
- `static/`: Static files (CSS, JavaScript, images like `FHIRVINE.png`).
- `docker-compose.yml`: Docker Compose configuration.
- `Dockerfile`: Docker container configuration.

## Contributing

Contributions are welcome! Please fork the repository, create a new branch, and submit a pull request with your changes. Ensure your code follows PEP 8 standards and includes appropriate tests.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For support or inquiries, contact the development team at `support@fhirvine.example.com`.