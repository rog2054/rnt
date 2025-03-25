from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()  # Initialize without app


class DeviceCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uname = db.Column(db.String(100), nullable=False)
    pw = db.Column(db.String(100), nullable=True)
    pwexpiry = db.Column(db.Boolean, default=False)
    
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname = db.Column(db.String(100), nullable=False)
    devicemgmtip = db.Column(db.String(100), nullable=False)
    devicesiteinfo = db.Column(db.String(100))
    deviceusername_id = db.Column(
        db.Integer,
        db.ForeignKey('device_credential.id', name="fk_device_username"),
        nullable=True
    )
    deviceusername = db.relationship('DeviceCredential', backref='devices')
    devicelanip = db.Column(db.String(100))
    # traceroute 10.174.88.1 source 10.55.33.253 numeric

class ASPathTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname = Device.devicehostname
    testprefix = db.Column(db.String(100), nullable=False)
    checkASinpath = db.Column(db.String(30), nullable=False)
    checkASwantresult = db.Column(db.Boolean)
    testtext = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')

class TracerouteTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname = Device.devicehostname
    testdest = db.Column(db.String(100), nullable=False)
    testtext = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')