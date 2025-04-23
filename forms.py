import re
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, URLField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, Optional, URL, Regexp, ValidationError

# Custom validator for space-separated URIs
def validate_uris(form, field):
    uris = field.data.split()
    for uri in uris:
        if not uri.startswith(('http://', 'https://')):
            raise ValidationError(f'Invalid URI format: "{uri}". Must start with http:// or https://.')
        if ' ' in uri:
            raise ValidationError(f'URI cannot contain spaces: "{uri}"')

# Custom validator for space-separated scopes
def validate_scopes(form, field):
    scopes = field.data.split()
    scope_pattern = r'^[a-zA-Z0-9\/\.\*\-]+$' 
    for scope in scopes:
        if not re.match(scope_pattern, scope):
            raise ValidationError(f'Invalid scope format: "{scope}". Allowed characters: a-z A-Z 0-9 / . * -')

class RegisterAppForm(FlaskForm):
    """Form for registering a new SMART application."""
    app_name = StringField(
        'Application Name',
        validators=[DataRequired(), Length(min=3, max=100)]
    )
    redirect_uris = TextAreaField(
        'Redirect URIs (Space-separated)',
        validators=[DataRequired(), validate_uris],
        description='Enter one or more valid redirect URIs, separated by spaces. Example: https://myapp.com/callback https://localhost:3000/cb'
    )
    scopes = TextAreaField(
        'Allowed Scopes (Space-separated)',
        validators=[DataRequired(), validate_scopes],
        default='openid profile launch launch/patient patient/*.read offline_access',
        description='Enter the scopes this application is allowed to request, separated by spaces. Standard SMART scopes recommended.'
    )
    logo_uri = URLField(
        'Logo URI (Optional)',
        validators=[Optional(), URL()],
        description='A URL pointing to an image for the application logo.'
    )
    contacts = TextAreaField(
        'Contacts (Optional, space-separated)',
        description='Contact email addresses (e.g., mailto:dev@example.com) or URLs, separated by spaces.'
    )
    tos_uri = URLField(
        'Terms of Service URI (Optional)',
        validators=[Optional(), URL()],
        description='Link to the application\'s Terms of Service.'
    )
    policy_uri = URLField(
        'Privacy Policy URI (Optional)',
        validators=[Optional(), URL()],
        description='Link to the application\'s Privacy Policy.'
    )
    submit = SubmitField('Register Application')

class TestClientForm(FlaskForm):
    """Form for testing SMART app launches."""
    client_id = StringField(
        'Client ID',
        validators=[DataRequired(), Length(min=1, max=100)]
    )
    submit = SubmitField('Launch Test')