from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()  # Initialize without app


class DeviceCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=True)
    passwordexpiry = db.Column(db.Boolean, default=False)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    mgmtip = db.Column(db.String(100), nullable=False)
    devicetype = db.Column(db.String(100))
    siteinfo = db.Column(db.String(100))
    username_id = db.Column(
        db.Integer,
        db.ForeignKey('device_credential.id', name="fk_device_username"),
        nullable=True
    )
    username = db.relationship('DeviceCredential', backref='devices')
    lanip = db.Column(db.String(100))
    numerictraceroute = db.Column(db.Boolean, default=True)
    tests = db.relationship("TestInstance", backref="device")
    # traceroute 10.174.88.1 source 10.55.33.253 numeric


class bgpaspathTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname_id = db.Column(
        db.Integer,
        db.ForeignKey('device.id', name='fk_device_hostname'),
        nullable=True
    )
    devicehostname = db.relationship('Device', backref='bgpaspathTests')
    testipv4prefix = db.Column(db.String(100), nullable=False)
    checkasinpath = db.Column(db.String(30), nullable=False)
    checkaswantresult = db.Column(db.Boolean, default=False, nullable=False)
    description = db.Column(db.String(200))
    instances = db.relationship("TestInstance", backref="bgpaspath_test")


class tracerouteTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname_id = db.Column(
        db.Integer,
        db.ForeignKey('device.id', name='fk_device_hostname'),
        nullable=True
    )
    devicehostname = db.relationship('Device', backref='tracerouteTests')
    destinationip = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    instances = db.relationship("TestInstance", backref="traceroute_test")


class TestRun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    # e.g., "Tests before changes"
    description = db.Column(db.String(200), nullable=False)
    # "pending", "running", "completed"
    status = db.Column(db.String(20), default="pending")
    # Relationships
    tests = db.relationship("TestInstance", backref="test_run")


class TestInstance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_run_id = db.Column(db.Integer, db.ForeignKey(
        "test_run.id"), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey(
        "device.id"), nullable=False)
    # e.g., "bgp_as_path", "traceroute_test"
    test_type = db.Column(db.String(50), nullable=False)
    # "pending", "running", "completed"
    status = db.Column(db.String(20), default="pending")
    # Foreign keys to specific test configs
    bgpaspath_test_id = db.Column(
        db.Integer, db.ForeignKey("bgpaspath_test.id"), nullable=True)
    traceroute_test_id = db.Column(
        db.Integer, db.ForeignKey("traceroute_test.id"), nullable=True)
    # Add more test type IDs as needed (e.g., other_test_id)


class bgpaspathTestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_instance_id = db.Column(db.Integer, db.ForeignKey(
        "test_instance.id"), nullable=False)
    # Raw Netmiko output (e.g. show command output)
    rawoutput = db.Column(db.Text)
    # Filtered output (e.g. just the line we have identified)
    output = db.Column(db.Text)
    # Was the AS there/not-there as required in the test definition?
    passed = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class tracerouteTestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_instance_id = db.Column(db.Integer, db.ForeignKey(
        "test_instance.id"), nullable=False)
    rawoutput = db.Column(db.Text)  # Traceroute output
    numberofhops = db.Column(db.Integer)
    # Not sure what determines a pass result for this test? Field for future use.
    passed = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
