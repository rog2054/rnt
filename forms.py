from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired, IPAddress
from models import DeviceCredential

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
