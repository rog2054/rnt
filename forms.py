from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired, IPAddress, Regexp, ValidationError
from models import DeviceCredential, Device
import ipaddress

def validate_ipv4_prefix(form, field):
    try:
        # Parse the input as an IPv4 network
        network = ipaddress.ip_network(field.data, strict=True)
        # Ensure it’s IPv4 (not IPv6)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValidationError("Must be an IPv4 prefix (e.g., 10.10.10.0/24)")
    except ValueError as e:
        raise ValidationError(f"Invalid IPv4 prefix: {str(e)}")
    
class DeviceForm(FlaskForm):
    device_name = StringField("Hostname", validators=[DataRequired()])
    device_mgmtip = StringField("Mgmt IP", validators=[DataRequired(), IPAddress()])
    
    # Dropdown field populated dynamically
    device_username = SelectField("SSH User", choices=[], coerce=int)
    
    device_siteinfo = StringField("Site info/type")
    device_lanip = StringField("LAN interface IP", validators=[IPAddress()])
    
    device_supportsnumerictraceroute = BooleanField("Supports numeric traceroute?", default="checked", render_kw={'checked':''})
    
    submit = SubmitField("Save Device")

    def __init__(self, *args, **kwargs):
        super(DeviceForm, self).__init__(*args, **kwargs)
        self.device_username.choices = [(cred.id, cred.uname) for cred in DeviceCredential.query.all()]

class CredentialForm(FlaskForm):
    uname = StringField("Username", validators=[DataRequired()])
    pw = StringField("Password")
    pwexpiry = BooleanField("Password expires?", default=False)
    
class bgpASpathTestForm(FlaskForm):
    test_device_hostname=SelectField("Test from Device", choices=[], coerce=int)
    test_testprefix = StringField(
        "Prefix to check",
        validators=[validate_ipv4_prefix]
    )
    test_checkASinpath = StringField(
    "ASN to check for",
    validators=[
        Regexp(r"^\d{3,5}$", message="AS number must be 3 to 5 digits")
    ]
    )
    test_checkASwantresult = BooleanField("AS should exist in the as-path?")
    test_testtext = StringField("What is the purpose of doing this test")
    
    submit = SubmitField("Save Test")
    
    def __init__(self, *args, **kwargs):
        super(bgpASpathTestForm, self).__init__(*args, **kwargs)
        self.test_device_hostname.choices = [(device.id, device.devicehostname) for device in Device.query.all()]
        
class tracerouteTestForm(FlaskForm):
    test_device_hostname=SelectField("Test from Device", choices=[], coerce=int)
    test_destinationip=StringField("Traceroute destination IP", validators=[DataRequired(), IPAddress()])
    test_testtext = StringField("What is the purpose of doing this test")
    
    submit = SubmitField("Save Test")
    
    def __init__(self, *args, **kwargs):
        super(tracerouteTestForm, self).__init__(*args, **kwargs)
        self.test_device_hostname.choices = [(device.id, device.devicehostname) for device in Device.query.all()]
        

class TestRunForm(FlaskForm):
    description = StringField("Test Run Description", validators=[DataRequired(message="Description is required")])
    submit = SubmitField("Run Tests")