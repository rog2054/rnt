from datetime import datetime
from flask_login import UserMixin
import bcrypt
from extensions import cipher, db
import json
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_user_created_by_id'), nullable=True)
    created_by = db.relationship('User', remote_side=[id], backref='created_users')
    theme = db.Column(db.String(20), nullable=True, default='calmblue')  # set a default theme
    user_timezone = db.Column(db.String(100), default="UTC", nullable=True)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
class DeviceCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=True)
    passwordexpiry = db.Column(db.Boolean, default=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_devicecredential_created_by_id'), nullable=True)
    created_by = db.relationship('User', backref='devicecredentials')
    hidden = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        """Encrypt and set the password."""
        self.password = cipher.encrypt(password.encode()).decode('utf-8')

    def get_password(self):
        """Decrypt and return the password, encrypting cleartext if found."""
        if self.password and len(self.password) < 50:  # Assume cleartext if < 50 chars
            # Encrypt the cleartext password and update the database
            cleartext = self.password
            self.set_password(cleartext)
            db.session.commit()  # Save the encrypted version
            return cleartext  # Return the original cleartext for this call
        return cipher.decrypt(self.password.encode()).decode('utf-8')


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
    active = db.Column(db.Boolean, default=True)
    hidden = db.Column(db.Boolean, default=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_device_created_by_id'), nullable=True)
    created_by = db.relationship('User', backref='devices')
    tests = db.relationship("TestInstance", backref="device")
    # traceroute 10.174.88.1 source 10.55.33.253 numeric

test_group_association = db.Table(
    'test_group_association',
    db.Column('test_id', db.Integer, nullable=False),
    db.Column('test_type', db.String(50), nullable=False),
    db.Column('group_id', db.Integer, db.ForeignKey('test_group.id'), nullable=False),
    db.UniqueConstraint('test_id', 'test_type', 'group_id', name='uq_test_group')
)

class TestGroup(db.Model):
    __tablename__ = 'test_group'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_testgroup_created_by_id'), nullable=False)
    
class bgpaspathTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname_id = db.Column(
        db.Integer,
        db.ForeignKey('device.id', name='fk_bgpaspath_device_hostname'),
        nullable=True
    )
    devicehostname = db.relationship('Device', backref='bgpaspathTests')
    testipv4prefix = db.Column(db.String(100), nullable=False)
    checkasinpath = db.Column(db.String(30), nullable=False)
    checkaswantresult = db.Column(db.Boolean, default=False, nullable=False)
    description = db.Column(db.String(200))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_bgpaspathtest_created_by_id'), nullable=True)
    created_by = db.relationship('User', backref='bgpaspathtests')
    hidden = db.Column(db.Boolean, default=False)
    instances = db.relationship("TestInstance", backref="bgpaspath_test")
    groups = db.relationship(
        'TestGroup',
        secondary=test_group_association,
        primaryjoin="and_(bgpaspathTest.id == test_group_association.c.test_id, test_group_association.c.test_type == 'bgpaspath_test')",
        backref=db.backref('bgpaspath_tests', lazy='dynamic')
    )

class tracerouteTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname_id = db.Column(
        db.Integer,
        db.ForeignKey('device.id', name='fk_traceroute_device_hostname'),
        nullable=True
    )
    devicehostname = db.relationship('Device', backref='tracerouteTests')
    destinationip = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_traceroutetest_created_by_id'), nullable=True)
    created_by = db.relationship('User', backref='traceroutetests')
    hidden = db.Column(db.Boolean, default=False)
    instances = db.relationship("TestInstance", backref="traceroute_test")
    groups = db.relationship(
        'TestGroup',
        secondary=test_group_association,
        primaryjoin="and_(tracerouteTest.id == test_group_association.c.test_id, test_group_association.c.test_type == 'traceroute_test')",
        backref=db.backref('traceroute_tests', lazy='dynamic')
    )

class pingTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname_id = db.Column(
        db.Integer,
        db.ForeignKey('device.id', name='fk_ping_device_hostname'),
        nullable=True
    )
    devicehostname = db.relationship('Device', backref='pingTests')
    destinationip = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_pingtest_created_by_id'), nullable=True)
    created_by = db.relationship('User', backref='pingtests')
    hidden = db.Column(db.Boolean, default=False)
    instances = db.relationship("TestInstance", backref="ping_test")
    groups = db.relationship(
        'TestGroup',
        secondary=test_group_association,
        primaryjoin="and_(pingTest.id == test_group_association.c.test_id, test_group_association.c.test_type == 'ping_test')",
        backref=db.backref('ping_tests', lazy='dynamic')
    )

class txrxtransceiverTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname_id = db.Column(
        db.Integer,
        db.ForeignKey('device.id', name='fk_txrxtransceiver_device_hostname'),
        nullable=True
    )
    devicehostname = db.relationship('Device',backref='txrxtransceiver_tests')
    deviceinterface = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_txrxtransceivertest_created_by_id'), nullable=True)
    created_by = db.relationship('User', backref='txrxtransceivertests')
    hidden = db.Column(db.Boolean, default=False)
    instances = db.relationship("TestInstance", backref="txrxtransceiver_test")
    groups = db.relationship(
        'TestGroup',
        secondary=test_group_association,
        primaryjoin="and_(txrxtransceiverTest.id == test_group_association.c.test_id, test_group_association.c.test_type == 'txrxtransceiver_test')",
        backref=db.backref('txrxtransceiver_tests', lazy='dynamic')
    )

class itracerouteTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname_id = db.Column(
        db.Integer,
        db.ForeignKey('device.id', name='fk_itraceroute_device_hostname'),
        nullable=True
    )
    devicehostname = db.relationship('Device',backref='itraceroute_tests')
    srcip = db.Column(db.String(100), nullable=False)
    dstip = db.Column(db.String(100), nullable=False)
    vrf = db.Column(db.String(100), nullable=False)
    encapvlan = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_itraceroutetest_created_by_id'), nullable=True)
    created_by = db.relationship('User', backref='itraceroutetests')
    hidden = db.Column(db.Boolean, default=False)
    instances = db.relationship("TestInstance", backref="itraceroute_test")
    groups = db.relationship(
        'TestGroup',
        secondary=test_group_association,
        primaryjoin="and_(itracerouteTest.id == test_group_association.c.test_id, test_group_association.c.test_type == 'itraceroute_test')",
        backref=db.backref('itraceroute_tests', lazy='dynamic')
    )

class customshowcommandTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    devicehostname_id = db.Column(
        db.Integer,
        db.ForeignKey('device.id', name='fk_customshowcommand_device_hostname'),
        nullable=True
    )
    devicehostname = db.relationship('Device',backref='customshowcommand_tests')
    customshowcommand = db.Column(db.String(200))
    description = db.Column(db.String(200))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_customshowcommandtest_created_by_id'), nullable=True)
    created_by = db.relationship('User', backref='customshowcommandtests')
    hidden = db.Column(db.Boolean, default=False)
    instances = db.relationship("TestInstance", backref="customshowcommand_test")
    groups = db.relationship(
        'TestGroup',
        secondary=test_group_association,
        primaryjoin="and_(customshowcommandTest.id == test_group_association.c.test_id, test_group_association.c.test_type == 'customshowcommand_test')",
        backref=db.backref('customshowcommand_tests', lazy='dynamic')
    )
     


class TestRun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, default=None)
    # e.g., "Tests before changes"
    description = db.Column(db.String(200), nullable=False)
    # "pending", "running", "completed"
    status = db.Column(db.String(20), default="pending")
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_testrun_created_by_id'), nullable=True)
    created_by = db.relationship('User', backref='testruns')
    hidden = db.Column(db.Boolean, default=False)
    log = db.Column(db.Text, nullable=True)
    # Relationships
    tests = db.relationship("TestInstance", backref="test_run")


class TestInstance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_run_id = db.Column(db.Integer, db.ForeignKey(
        "test_run.id", name='fk_test_instance_test_run'), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey(
        "device.id", name='fk_test_instance_device'), nullable=False)
    # e.g., "bgpaspath", "traceroute_test"
    test_type = db.Column(db.String(50), nullable=False)
    # "pending", "running", "completed"
    status = db.Column(db.String(20), default="pending")
    # Foreign keys to specific test configs
    bgpaspath_test_id = db.Column(
        db.Integer, db.ForeignKey("bgpaspath_test.id", name='fk_test_instance_bgpaspath_test'), nullable=True)
    traceroute_test_id = db.Column(
        db.Integer, db.ForeignKey("traceroute_test.id", name='fk_test_instance_traceroute_test'), nullable=True)
    ping_test_id = db.Column(db.Integer, db.ForeignKey("ping_test.id", name='fk_test_instance_ping_test'), nullable=True)
    txrxtransceiver_test_id = db.Column(db.Integer, db.ForeignKey("txrxtransceiver_test.id", name='fk_test_instance_txrxtransceiver_test'), nullable=True)
    itraceroute_test_id = db.Column(db.Integer, db.ForeignKey("itraceroute_test.id", name='fk_test_instance_itraceroute_test'), nullable=True)
    customshowcommand_test_id = db.Column(db.Integer, db.ForeignKey("customshowcommand_test.id", name='fk_test_instance_customshowcommand_test'), nullable=True)
    device_active_at_run = db.Column(db.Boolean, nullable=False, default=True)


class bgpaspathTestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_instance_id = db.Column(db.Integer, db.ForeignKey(
        "test_instance.id", name='fk_bgpaspath_result_test_instance'), nullable=False)
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
        "test_instance.id", name='fk_traceroute_result_test_instance'), nullable=False)
    rawoutput = db.Column(db.Text)  # Traceroute output
    numberofhops = db.Column(db.Integer)
    passed = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class pingTestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_instance_id = db.Column(db.Integer, db.ForeignKey(
        "test_instance.id", name='fk_ping_result_test_instance'), nullable=False)
    rawoutput = db.Column(db.Text)  # Ping output
    passed = db.Column(db.Boolean)  # we will do 100 pings, a Pass is 100/100 in found in the output, if that value isn't found then the result is Fail
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
class txrxtransceiverTestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_instance_id = db.Column(db.Integer, db.ForeignKey("test_instance.id", name='fk_txfxtransceiver_result_test_instance'), nullable=False)
    rawoutput = db.Column(db.Text)
    sfpinfo = db.Column(db.Text)
    txrx = db.Column(db.Text)
    passed = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def sfpinfo_dict(self):
        """Deserialize sfpinfo JSON string to dict when accessed."""
        if self.sfpinfo:
            return json.loads(self.sfpinfo)
        return None

    @sfpinfo_dict.setter
    def sfpinfo_dict(self, value):
        """Serialize dict to JSON string when setting sfpinfo."""
        self.sfpinfo = json.dumps(value) if value is not None else None

    @property
    def txrx_dict(self):
        """Deserialize txrx JSON string to dict when accessed."""
        if self.txrx:
            return json.loads(self.txrx)
        return None

    @txrx_dict.setter
    def txrx_dict(self, value):
        """Serialize dict to JSON string when setting txrx."""
        self.txrx = json.dumps(value) if value is not None else None
    
class itracerouteTestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_instance_id = db.Column(db.Integer, db.ForeignKey("test_instance.id", name='fk_itraceroute_result_test_instance'), nullable=False)
    rawoutput = db.Column(db.Text)
    passed = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class customshowcommandTestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_instance_id = db.Column(db.Integer, db.ForeignKey("test_instance.id", name='fk_customshowcommand_result_test_instance'), nullable=False)
    rawoutput = db.Column(db.Text)
    passed = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    command_executed = db.Column(db.String(250))
