from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

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
    devicesupportsnumerictraceroute = db.Column(db.Boolean, default=True)
    tests = db.relationship("TestInstance", backref="device")
    # traceroute 10.174.88.1 source 10.55.33.253 numeric

class bgpASpathTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname_id = db.Column(
        db.Integer,
        db.ForeignKey('device.id', name='fk_device_hostname'),
        nullable=True
    )
    devicehostname = db.relationship('Device', backref='bgpASpathTests')
    testprefix = db.Column(db.String(100), nullable=False)
    checkASinpath = db.Column(db.String(30), nullable=False)
    checkASwantresult = db.Column(db.Boolean, default=False, nullable=False)
    testtext = db.Column(db.String(200))
    instances = db.relationship("TestInstance", backref="bgp_aspath_test")    

class tracerouteTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname_id = db.Column(
        db.Integer,
        db.ForeignKey('device.id', name='fk_device_hostname'),
        nullable=True
    )
    devicehostname = db.relationship('Device', backref='tracerouteTests')
    destinationip = db.Column(db.String(100), nullable=False)
    testtext = db.Column(db.String(200))
    instances = db.relationship("TestInstance", backref="traceroute_test")    
    
class TestRun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(200), nullable=False)  # e.g., "Tests before changes"
    status = db.Column(db.String(20), default="pending")  # "pending", "running", "completed"
    # Relationships
    tests = db.relationship("TestInstance", backref="test_run")
    
class TestInstance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_run_id = db.Column(db.Integer, db.ForeignKey("test_run.id"), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    test_type = db.Column(db.String(50), nullable=False)  # e.g., "bgp_as_path", "traceroute_test"
    status = db.Column(db.String(20), default="pending")  # "pending", "running", "completed"
    # Foreign keys to specific test configs
    bgp_aspath_test_id = db.Column(db.Integer, db.ForeignKey("bgp_a_spath_test.id"), nullable=True)
    traceroute_test_id = db.Column(db.Integer, db.ForeignKey("traceroute_test.id"), nullable=True)
    # Add more test type IDs as needed (e.g., other_test_id)
    
class bgpASpathResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_instance_id = db.Column(db.Integer, db.ForeignKey("test_instance.id"), nullable=False)
    rawoutput = db.Column(db.Text)  # Raw Netmiko output (e.g., BGP table)
    output = db.Column(db.Text)  # Filtered output (e.g. only relevant lines)
    passed = db.Column(db.Boolean)  # Was the AS there/not-there as required in the test definition?
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class tracerouteTestResult(db.Model):  
    id = db.Column(db.Integer, primary_key=True)
    test_instance_id = db.Column(db.Integer, db.ForeignKey("test_instance.id"), nullable=False)
    rawoutput = db.Column(db.Text)  # Traceroute output
    numberofhops = db.Column(db.Integer)
    passed = db.Column(db.Boolean)  # Not sure what determines a pass result for this test? Field for future use.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    