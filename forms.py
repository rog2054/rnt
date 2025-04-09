from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, IPAddress, Regexp, ValidationError, Length
from models import DeviceCredential, Device
import ipaddress


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

class TestRunForm(FlaskForm):
    description = StringField("Test Run Description", validators=[
                              DataRequired(message="Description is required")])
    submit = SubmitField("Run Tests")
