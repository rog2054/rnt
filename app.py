from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
import threading
from time import sleep  # Simulated test execution

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///config.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
db = SQLAlchemy(app)
socketio = SocketIO(app)

# Models

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
    deviceusername = DeviceCredential.uname
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
    
with app.app_context():
    db.create_all()

# Routes
@app.route('/credentials', methods=['GET', 'POST'])
def credentials():
    if request.method == 'POST':
        uname = request.form['uname']
        pw = request.form['pw']
        is_pwexpiry = 'pwexpiry' in request.form
        new_credential = DeviceCredential(uname=uname, pw=pw, pwexpiry=is_pwexpiry)
        db.session.add(new_credential)
        db.session.commit()
        return jsonify({'message': 'Credentails added'})
    credentials = DeviceCredential.query.all()
    return render_template('credentials.html', credentials=credentials)

@app.route('/devices', methods=['GET', 'POST'])
def devices():
    if request.method == 'POST':
        device_name = request.form['device_name']
        device_mgmtip = request.form['device_mgmtip']
        device_username = request.form['device_username']
        device_siteinfo = request.form['device_siteinfo']
        device_lanip = request.form['device_lanip']
        new_device = Device(devicehostname=device_name, devicemgmtip=device_mgmtip, deviceusername=device_username, devicesiteinfo=device_siteinfo, devicelanip=device_lanip)
        db.session.add(new_device)
        db.session.commit()
        return jsonify({'message': 'Device added'})
    devices = Device.query.all()
    return render_template('devices.html', devices=devices)

@app.route('/tests', methods=['GET', 'POST'])
def tests():
    if request.method == 'POST':
        test_name = request.form['test_name']
        category = request.form['category']
        parameter = request.form['parameter']
        new_test = TestConfig(test_name=test_name, category=category, parameter=parameter)
        db.session.add(new_test)
        db.session.commit()
        return jsonify({'message': 'Test added successfully'})
    categories = [cat[0] for cat in db.session.query(TestConfig.category).distinct().all()]
    tests = TestConfig.query.all()
    return render_template('tests.html', categories=categories, tests=tests)

@app.route('/delete_test/<int:test_id>', methods=['POST'])
def delete_test(test_id):
    test = TestConfig.query.get_or_404(test_id)
    db.session.delete(test)
    db.session.commit()
    return jsonify({'message': 'Test deleted successfully'})

@app.route('/run_tests', methods=['GET', 'POST'])
def run_tests():
    tests = TestConfig.query.all()
    devices = Device.query.all()
    dynamic_devices = [d for d in devices if d.is_dynamic]
    if dynamic_devices:
        socketio.emit('password_prompt', {
            'devices': [{'id': d.id, 'device_name': d.device_name, 'username': d.username} for d in dynamic_devices]
        }, namespace='/test')
    return render_template('run_tests.html', tests=tests)

def run_test_group(group_name, tests):
    total = len(tests)
    for i, test in enumerate(tests, 1):
        sleep(1)  # Replace with Netmiko logic
        test.status = 'passed' if hash(test.test_name) % 2 == 0 else 'failed'
        db.session.commit()
        socketio.emit('progress', {
            'group': group_name,
            'completed': i,
            'total': total,
            'percentage': (i / total) * 100
        }, namespace='/test')

@app.route('/start_tests', methods=['GET'])
def start_tests():
    tests = TestConfig.query.all()
    grouped_tests = {}
    for test in tests:
        test.status = 'running'
        grouped_tests.setdefault(test.category, []).append(test)
    db.session.commit()
    threads = []
    max_threads = 3
    for group_name, group_tests in list(grouped_tests.items())[:max_threads]:
        t = threading.Thread(target=run_test_group, args=(group_name, group_tests))
        threads.append(t)
        t.start()
    return jsonify({'message': 'Tests started'})

@socketio.on('submit_passwords', namespace='/test')
def handle_passwords(data):
    passwords = data['passwords']
    for device_id, password in passwords.items():
        device = Device.query.get(device_id)
        if device and device.is_dynamic:
            device.password = password
    db.session.commit()
    socketio.emit('start_tests', namespace='/test')

if __name__ == '__main__':
    socketio.run(app, debug=True)
    