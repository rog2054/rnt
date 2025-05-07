from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, BooleanField, PasswordField, HiddenField
from wtforms.validators import DataRequired, IPAddress, Regexp, ValidationError, Length, EqualTo
from models import DeviceCredential, Device, TestRun
import ipaddress
from extensions import db
from utils import format_datetime_with_ordinal

def validate_ipv4_prefix(form, field):
    try:
        # Parse the input as an IPv4 network
        network = ipaddress.ip_network(field.data, strict=True)
        # Ensure it’s IPv4 (not IPv6)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValidationError(
                "Must be an IPv4 prefix (e.g., 10.10.10.0/24)")
    except ValueError as e:
        raise ValidationError(f"Invalid IPv4 prefix: {str(e)}")


# User Creation Form
class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=120)])
    submit = SubmitField('Create User')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=120)])
    submit = SubmitField('Login')

class DeviceForm(FlaskForm):
    hostname = StringField("Hostname", validators=[DataRequired()])
    mgmtip = StringField("Mgmt IP", validators=[DataRequired(), IPAddress()])
    devicetype = SelectField(
        'Device Type:',
        choices=[
            ('cisco_ios', 'Cisco IOS'),
            ('cisco_nxos', 'Cisco NX OS'),
            ('cisco_aci', 'Cisco ACI Leaf')
        ],
        coerce=str  # This ensures that the selected value is returned as a string
    )
    submit = SubmitField('Submit')

    # Dropdown field populated dynamically
    username = SelectField("SSH User", choices=[], coerce=int)

    siteinfo = StringField("Site info/type")
    lanip = StringField("LAN interface IP", validators=[IPAddress()])

    numerictraceroute = BooleanField(
        "Supports numeric traceroute?", default="checked", render_kw={'checked': ''})

    submit = SubmitField("Save Device")

    def __init__(self, *args, **kwargs):
        super(DeviceForm, self).__init__(*args, **kwargs)
        self.username.choices = [(cred.id, cred.username)
                                 for cred in DeviceCredential.query.all()]


class CredentialForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = StringField("Password")
    passwordexpiry = BooleanField("Password expires?", default=False)
    submit = SubmitField("Save User")


class bgpaspathTestForm(FlaskForm):
    test_device_hostname = SelectField(
        "Test from Device", choices=[], coerce=int)
    test_ipv4prefix = StringField(
        "Prefix to check",
        validators=[validate_ipv4_prefix]
    )
    test_checkasinpath = StringField(
        "ASN to check for",
        validators=[
            Regexp(r"^\d{3,5}$", message="AS number must be 3 to 5 digits")
        ]
    )
    test_checkaswantresult = BooleanField("AS should exist in the as-path?")
    test_description = StringField("What is the purpose of doing this test")

    submit = SubmitField("Save Test")

    def __init__(self, *args, **kwargs):
        super(bgpaspathTestForm, self).__init__(*args, **kwargs)
        self.test_device_hostname.choices = [
        (device.id, device.hostname)
        for device in Device.query
            .filter(Device.devicetype.in_(["cisco_ios", "cisco_nxos"]))
            .order_by(Device.hostname)
            .all()
        ]


class tracerouteTestForm(FlaskForm):
    test_device_hostname = SelectField(
        "Test from Device", choices=[], coerce=int)
    test_destinationip = StringField("Traceroute destination IP", validators=[
                                     DataRequired(), IPAddress()])
    test_description = StringField("What is the purpose of doing this test")

    submit = SubmitField("Save Test")

    def __init__(self, *args, **kwargs):
        super(tracerouteTestForm, self).__init__(*args, **kwargs)
        self.test_device_hostname.choices = [
        (device.id, device.hostname)
        for device in Device.query
            .filter(Device.devicetype.in_(["cisco_ios", "cisco_nxos"]))
            .order_by(Device.hostname)
            .all()
        ]

class pingTestForm(FlaskForm):
    test_device_hostname = SelectField(
        "Test from Device", choices=[], coerce=int)
    test_destinationip = StringField("Ping destination IP", validators=[
                                     DataRequired(), IPAddress()])
    test_description = StringField("What is the purpose of doing this test")

    submit = SubmitField("Save Test")

    def __init__(self, *args, **kwargs):
        super(tracerouteTestForm, self).__init__(*args, **kwargs)
        self.test_device_hostname.choices = [
        (device.id, device.hostname)
        for device in Device.query
            .filter(Device.devicetype.in_(["cisco_ios", "cisco_nxos"]))
            .order_by(Device.hostname)
            .all()
        ]

class txrxtransceiverTestForm(FlaskForm):
    test_device_hostname = SelectField(
        "Test from Device", choices=[], coerce=int)
    test_deviceinterface = StringField("Interface name", validators=[
                                     DataRequired()])
    test_description = StringField("What is the purpose of doing this test")

    submit = SubmitField("Save Test")

    def __init__(self, *args, **kwargs):
        super(txrxtransceiverTestForm, self).__init__(*args, **kwargs)
        self.test_device_hostname.choices = [
        (device.id, device.hostname)
        for device in Device.query
            .filter(Device.devicetype.in_(["cisco_ios", "cisco_nxos"]))
            .order_by(Device.hostname)
            .all()
        ]

class itracerouteTestForm(FlaskForm):
    test_device_hostname = SelectField(
        "Test from Device", choices=[], coerce=int)
    test_srcip = StringField("Source IP", validators=[
                                     DataRequired(), IPAddress()])
    test_dstip = StringField("Destination IP", validators=[
                                     DataRequired(), IPAddress()])
    test_vrf = StringField("vrf", validators=[
                                     DataRequired()])
    test_encapvlan = StringField("encap vlan", validators=[
                                     DataRequired()])
    test_description = StringField("What is the purpose of doing this test")

    submit = SubmitField("Save Test")

    def __init__(self, *args, **kwargs):
        super(itracerouteTestForm, self).__init__(*args, **kwargs)
        self.test_device_hostname.choices = [
        (device.id, device.hostname)
        for device in Device.query
            .filter(Device.devicetype.in_(["cisco_aci"]))
            .order_by(Device.hostname)
            .all()
        ]

class TestRunForm(FlaskForm):
    description = StringField("Test Run Description", validators=[
                              DataRequired(message="Description is required")])
    submit = SubmitField("Run Tests")


class CompareTestRunsForm(FlaskForm):
    test_run_1 = SelectField(
        'Test Run A',
        validators=[DataRequired()],
        coerce=int,  # Convert selected value to integer (TestRun.id)
        choices=[]   # Populated dynamically in the route
    )
    test_run_2 = SelectField(
        'Test Run B',
        validators=[DataRequired()],
        coerce=int,
        choices=[]
    )
    compare_type_x = SubmitField('Compare by Results (Pass/Fail)')
    compare_type_y = SubmitField('Compare CLI Output (exact)')

    def __init__(self, *args, **kwargs):
        super(CompareTestRunsForm, self).__init__(*args, **kwargs)
        # Populate choices with TestRun records (hidden=False)
        test_runs = db.session.query(TestRun).filter(TestRun.hidden == False).order_by(TestRun.start_time.desc()).all()
        self.test_run_1.choices = [
            (tr.id, f"ID: {tr.id}, {format_datetime_with_ordinal(tr.start_time)}, {tr.description}")
            for tr in test_runs
        ]
        self.test_run_2.choices = self.test_run_1.choices  # Same choices for both

    def validate(self, extra_validators=None):
        if not super(CompareTestRunsForm, self).validate(extra_validators):
            return False
        # Optional: Prevent selecting the same TestRun
        if self.test_run_1.data == self.test_run_2.data:
            self.test_run_2.errors.append("Please select different TestRuns for comparison.")
            return False
        return True
    
class ChangePasswordForm(FlaskForm):
    form_name = HiddenField('form_name',default='userpassword')
    current_password = PasswordField('Current Password', validators=[DataRequired(), Length(min=8)])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Change Password')
    
    def __init__(self, *args, **kwargs):
        super(ChangePasswordForm, self).__init__(*args, **kwargs)
        self.csrf_token.id = 'password_csrf_token'
        self.submit.id = 'password_submit'

class ThemeForm(FlaskForm):
    form_name = HiddenField('form_name', default='theme')
    theme = SelectField('Select Theme', choices=[('grey', 'Grey'), ('blue', 'Blue'), ('orange', 'Orange'), ('green', 'Green'), ('calmblue', 'Calm Blue')], validators=[DataRequired()])
    submit = SubmitField('Apply Theme')
    
    def __init__(self, current_theme=None, *args, **kwargs):
        super(ThemeForm, self).__init__(*args, **kwargs)
        self.csrf_token.id = 'theme_csrf_token'
        self.submit.id = 'theme_submit'
        # Set default theme if provided (for GET requests)
        if current_theme and current_theme in [choice[0] for choice in self.theme.choices]:
            self.theme.default = current_theme