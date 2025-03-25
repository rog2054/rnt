from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired, IPAddress, Regexp
from models import DeviceCredential, Device

class DeviceForm(FlaskForm):
    device_name = StringField("Hostname", validators=[DataRequired()])
    device_mgmtip = StringField("Mgmt IP", validators=[DataRequired(), IPAddress()])
    
    # Dropdown field populated dynamically
    device_username = SelectField("SSH User", choices=[], coerce=int)
    
    device_siteinfo = StringField("Site info/type")
    device_lanip = StringField("LAN interface IP", validators=[IPAddress()])
    
    submit = SubmitField("Save Device")

    def __init__(self, *args, **kwargs):
        super(DeviceForm, self).__init__(*args, **kwargs)
        self.device_username.choices = [(cred.id, cred.uname) for cred in DeviceCredential.query.all()]

class CredentialForm(FlaskForm):
    uname = StringField("Username", validators=[DataRequired()])
    pw = StringField("Password")
    pwexpiry = bool("Password expires?")
    
class bgpASpathTestForm(FlaskForm):
    test_device_hostname=SelectField("Test from Device", choices=[], coerce=int)
    test_testprefix=StringField("Prefix to check")
    test_checkASinpath = StringField(
    "ASN to check for",
    validators=[
        Regexp(r"^\d{3,5}$", message="AS number must be 3 to 5 digits")
    ]
    )
    test_checkASwantresult = BooleanField("AS should exist in the as-path?")
    test_testtext = StringField("What is the purpose of doing this test")
    
    def __init__(self, *args, **kwargs):
        super(bgpASpathTestForm, self).__init__(*args, **kwargs)
        self.test_device_hostname.choices = [(device.id, device.devicehostname) for device in Device.query.all()]
        