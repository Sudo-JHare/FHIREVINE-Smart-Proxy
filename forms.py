import re
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, URLField, SubmitField, HiddenField, IntegerField, RadioField
from wtforms.validators import DataRequired, Length, Optional, URL, Regexp, ValidationError, NumberRange

def validate_uris(form, field):
    uris = field.data.split()
    for uri in uris:
        if not uri.startswith(('http://', 'https://')):
            raise ValidationError(f'Invalid URI format: "{uri}". Must start with http:// or https://.')
        if ' ' in uri:
            raise ValidationError(f'URI cannot contain spaces: "{uri}"')

def validate_scopes(form, field):
    scopes = field.data.split()
    scope_pattern = r'^[a-zA-Z0-9\/\.\*\-_]+$'
    for scope in scopes:
        if not re.match(scope_pattern, scope):
            raise ValidationError(f'Invalid scope format: "{scope}". Allowed characters: a-z A-Z 0-9 / . * _ -')

def validate_optional_url(form, field):
    if field.data and field.data.strip():
        url_validator = URL(require_tld=False)
        url_validator(form, field)

class RegisterAppForm(FlaskForm):
    app_name = StringField(
        'Application Name',
        validators=[DataRequired(), Length(min=3, max=100)]
    )
    redirect_uris = TextAreaField(
        'Redirect URIs (Space-separated)',
        validators=[DataRequired(), validate_uris],
        description='Enter one or more valid redirect URIs, separated by spaces.'
    )
    scopes = TextAreaField(
        'Allowed Scopes (Space-separated)',
        validators=[DataRequired(), validate_scopes],
        default='openid profile launch launch/patient patient/*.read offline_access',
        description='Enter the scopes this application is allowed to request, separated by spaces.'
    )
    logo_uri = StringField(
        'Logo URI (Optional)',
        validators=[Optional(strip_whitespace=True), validate_optional_url],
        description='A URL pointing to an image for the application logo.'
    )
    contacts = TextAreaField(
        'Contacts (Optional, space-separated)',
        validators=[Optional(strip_whitespace=True)],
        description='Contact email addresses or URLs, separated by spaces.'
    )
    tos_uri = StringField(
        'Terms of Service URI (Optional)',
        validators=[Optional(strip_whitespace=True), validate_optional_url],
        description='Link to the application\'s Terms of Service.'
    )
    policy_uri = StringField(
        'Privacy Policy URI (Optional)',
        validators=[Optional(strip_whitespace=True), validate_optional_url],
        description='Link to the application\'s Privacy Policy.'
    )
    submit = SubmitField('Register Application')

class TestClientForm(FlaskForm):
    client_id = StringField(
        'Client ID',
        validators=[DataRequired(), Length(min=1, max=100)]
    )
    response_mode = RadioField(
        'Response Mode',
        choices=[
            ('inline', 'Display Response Inline'),
            ('redirect', 'Redirect to URL')
        ],
        default='inline'
    )
    submit = SubmitField('Launch Test')

class ConsentForm(FlaskForm):
    consent = HiddenField('Consent', validators=[DataRequired()])
    submit_allow = SubmitField('Allow')
    submit_deny = SubmitField('Deny')

class SecurityConfigForm(FlaskForm):
    token_duration = IntegerField(
        'Access Token Duration (seconds)',
        validators=[DataRequired(), NumberRange(min=300, max=86400)],
        default=3600,
        description='Duration for access tokens (300 to 86400 seconds).'
    )
    refresh_token_duration = IntegerField(
        'Refresh Token Duration (seconds)',
        validators=[DataRequired(), NumberRange(min=3600, max=604800)],
        default=86400,
        description='Duration for refresh tokens (3600 to 604800 seconds).'
    )
    allowed_scopes = TextAreaField(
        'Allowed Scopes (Space-separated)',
        validators=[DataRequired(), validate_scopes],
        default='openid profile launch launch/patient patient/*.read offline_access',
        description='Scopes allowed for all applications.'
    )
    submit = SubmitField('Save Security Settings')

class ProxyConfigForm(FlaskForm):
    fhir_server_url = URLField(
        'FHIR Server URL',
        validators=[DataRequired(), URL()],
        description='Base URL of the upstream FHIR server.'
    )
    proxy_timeout = IntegerField(
        'Proxy Timeout (seconds)',
        validators=[DataRequired(), NumberRange(min=5, max=60)],
        default=10,
        description='Timeout for proxy requests (5 to 60 seconds).'
    )
    submit = SubmitField('Save Proxy Settings')

class EndpointConfigForm(FlaskForm):
    metadata_endpoint = StringField(
        'Metadata Endpoint',
        validators=[DataRequired(), Length(min=1, max=255)],
        default='/metadata',
        description='Relative path to the FHIR server metadata endpoint (e.g., /metadata).'
    )
    capability_endpoint = StringField(
        'Capability Statement Endpoint',
        validators=[DataRequired(), Length(min=1, max=255)],
        default='/metadata',
        description='Relative path to the FHIR server capability statement (e.g., /metadata).'
    )
    resource_base_endpoint = StringField(
        'Resource Base Endpoint',
        validators=[DataRequired(), Length(min=1, max=255)],
        default='',
        description='Base path for FHIR resources (e.g., /baseR4).'
    )
    submit = SubmitField('Save Endpoint Settings')