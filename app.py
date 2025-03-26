from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_socketio import SocketIO
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
import threading
from time import sleep  # Simulated test execution
from models import db, DeviceCredential, Device, bgpASpathTest, tracerouteTest
from forms import DeviceForm, CredentialForm, bgpASpathTestForm, tracerouteTestForm

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///config.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'your-secret-key'

    db.init_app(app)  # Bind db to app
    migrate = Migrate(app, db)  # Enable migrations
    socketio.init_app(app)

    with app.app_context():
        db.create_all()  # Ensure tables exist

    return app

app = create_app()
CSRFProtect(app)

# Routes
@app.route('/credentials', methods=['GET', 'POST'])
def credentials():
    form = CredentialForm()
    if request.method == 'POST':
        uname = request.form['uname']
        pw = request.form['pw']
        is_pwexpiry = 'pwexpiry' in request.form
        new_credential = DeviceCredential(uname=uname, pw=pw, pwexpiry=is_pwexpiry)
        db.session.add(new_credential)
        db.session.commit()
        return jsonify({'message': 'Credentails added'})
    credentials = DeviceCredential.query.all()
    return render_template('credentials.html', credentials=credentials, form=form)

# Delete credential
@app.route('/delete_credential/<int:credential_id>', methods=['POST'])
def delete_credential(credential_id):
    credential = DeviceCredential.query.get_or_404(credential_id)
    db.session.delete(credential)
    db.session.commit()
    return jsonify({'message': 'Credential deleted successfully'})

@app.route('/devices')
def device_list():
    devices=Device.query.all()
    return render_template('devices.html', devices=devices)

# Route to display the add device form
@app.route('/devices/add', methods=['GET', 'POST'])
def device_add():
    form = DeviceForm()
    if request.method == 'POST':
        if form.validate_on_submit():  # Form validation
            try:
                # Create a new device using the form data
                new_device = Device(
                    devicehostname=form.device_name.data,
                    devicemgmtip=form.device_mgmtip.data,
                    deviceusername_id=form.device_username.data,  # Device username as selected from dropdown
                    devicesiteinfo=form.device_siteinfo.data,
                    devicelanip=form.device_lanip.data,
                    devicesupportsnumerictraceroute=form.device_supportsnumerictraceroute.data
                )
                db.session.add(new_device)
                db.session.commit()
                return jsonify({'redirect': url_for('device_list')})  # Redirect back to device list
            except Exception as e:
                db.session.rollback()  # In case of any error, rollback the session
                print("Error adding device:", str(e))
                return jsonify({'message': 'Database error: ' + str(e)}), 500
        # If form validation fails, return specific errors
        error_messages = {field: error for field, error in form.errors.items()}
        return jsonify({'message': 'Form validation failed', 'errors': error_messages}), 400
    return render_template("add_device.html", form=form)  # If GET request, render form

# Delete device
@app.route('/delete_device/<int:device_id>', methods=['POST'])
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    return jsonify({'message': 'Device removed successfully'})

# Display all AS-path tests
@app.route('/tests/bgpaspath', methods=['GET'])
def showtests_bgpaspath():
    bgpaspathtests=bgpASpathTest.query.all()
    return render_template('bgpaspathtests.html', bgpaspathtests=bgpaspathtests)

# Add AS-path test
@app.route('/tests/addtest_bgpaspath', methods=['GET', 'POST'])
def addtest_bgpaspath():
    form = bgpASpathTestForm()
    if request.method == 'POST':
        if form.validate_on_submit():  # Form validation
            try:
                # Create a new bgp as-path test using the form data
                new_test = bgpASpathTest(
                    devicehostname_id=form.test_device_hostname.data,
                    testprefix=form.test_testprefix.data,
                    checkASinpath=form.test_checkASinpath.data,
                    checkASwantresult=form.test_checkASwantresult.data,
                    testtext=form.test_testtext.data
                )
                db.session.add(new_test)
                db.session.commit()
                ''' return jsonify({'redirect': url_for('showtests_bgpaspath')})  # Redirect back to BGP as-path tests list '''
                return redirect(url_for('showtests_bgpaspath'))
            except Exception as e:
                db.session.rollback()  # In case of any error, rollback the session
                print("Error adding device:", str(e))
                return jsonify({'message': 'Database error: ' + str(e)}), 500
        # If form validation fails, return specific errors
        error_messages = {field: error for field, error in form.errors.items()}
        return jsonify({'message': 'Form validation failed', 'errors': error_messages}), 400
    return render_template("addtest_bgpaspath.html", form=form)  # If GET request, render form

# Delete AS-path Test
@app.route('/tests/delete_bgpaspathtest/<int:test_id>', methods=['POST'])
def delete_bgptest(test_id):
    test = bgpASpathTest.query.get_or_404(test_id)
    db.session.delete(test)
    db.session.commit()
    return jsonify({'message': 'BGP AS-path Test removed successfully'})

# Display all Traceroute Tests
@app.route('/tests/traceroute', methods=['GET'])
def showtests_traceroute():
    traceroutetests=tracerouteTest.query.all()
    return render_template('traceroutetests.html', traceroutetests=traceroutetests)

# Add Traceroute test
@app.route('/tests/addtest_traceroute', methods=['GET', 'POST'])
def addtest_traceroute():
    form = tracerouteTestForm()
    if request.method == 'POST':
        if form.validate_on_submit():  # Form validation
            try:
                # Create a new bgp as-path test using the form data
                new_test = tracerouteTest(
                    devicehostname_id=form.test_device_hostname.data,
                    destinationip=form.test_destinationip.data,
                    testtext=form.test_testtext.data
                )
                db.session.add(new_test)
                db.session.commit()
                ''' return jsonify({'redirect': url_for('showtests_traceroute')})  # Redirect back to BGP as-path tests list '''
                return redirect(url_for('showtests_traceroute'))
            except Exception as e:
                db.session.rollback()  # In case of any error, rollback the session
                print("Error adding device:", str(e))
                return jsonify({'message': 'Database error: ' + str(e)}), 500
        # If form validation fails, return specific errors
        error_messages = {field: error for field, error in form.errors.items()}
        return jsonify({'message': 'Form validation failed', 'errors': error_messages}), 400
    return render_template("addtest_traceroute.html", form=form)  # If GET request, render form

# Delete Traceroute Test
@app.route('/tests/delete_traceroutetest/<int:test_id>', methods=['POST'])
def delete_traceroutetest(test_id):
    test = tracerouteTest.query.get_or_404(test_id)
    db.session.delete(test)
    db.session.commit()
    return jsonify({'message': 'Traceroute Test removed successfully'})


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
    