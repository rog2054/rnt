from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_socketio import SocketIO
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from threading import Thread
from queue import Queue
from time import sleep  # Simulated test execution
from models import db, DeviceCredential, Device, bgpASpathTest, tracerouteTest, TestRun, TestInstance, bgpASpathTestResult, tracerouteTestResult
from forms import DeviceForm, CredentialForm, bgpASpathTestForm, tracerouteTestForm, TestRunForm
import netmiko
from netmiko import NetmikoTimeoutException, NetmikoAuthenticationException
import logging

# Configure logging for Debug/Error (console)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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

@app.route('/tests/progress/<int:run_id>')
def test_progress(run_id):
    test_run = TestRun.query.get_or_404(run_id)
    instances = TestInstance.query.filter_by(test_run_id=run_id).all()
    stats = {
        "bgp_as_path": {"completed": 0, "running": 0, "skipped": 0, "total": 0},
        "traceroute_test": {"completed": 0, "running": 0, "skipped": 0, "total": 0},
    }
    for inst in instances:
        stats[inst.test_type]["total"] += 1
        if inst.status == "completed":
            stats[inst.test_type]["completed"] += 1
        elif inst.status == "running":
            stats[inst.test_type]["running"] += 1
        elif inst.status == "skipped":
            stats[inst.test_type]["skipped"] += 1
    return render_template('test_progress.html', test_run=test_run, stats=stats, run_id=run_id)

@app.route('/tests/results/<int:run_id>')
def test_results(run_id):
    test_run = TestRun.query.get_or_404(run_id)
    instances = TestInstance.query.filter_by(test_run_id=run_id).all()
    return render_template('test_results.html', test_run=test_run, instances=instances)

@app.route('/tests/run', methods=['GET', 'POST'])
def run_tests():
    form = TestRunForm()
    if form.validate_on_submit():  # Handles POST and validation
        test_run = TestRun(description=form.description.data, status="running")
        db.session.add(test_run)
        db.session.commit()

        # Gather all test configurations
        test_instances = []
        bgp_tests = bgpASpathTest.query.all()
        for test in bgp_tests:
            instance = TestInstance(
                test_run_id=test_run.id,
                device_id=test.devicehostname_id,
                test_type="bgp_as_path",
                bgp_as_path_test_id=test.id
            )
            test_instances.append(instance)

        traceroute_tests = tracerouteTest.query.all()
        for test in traceroute_tests:
            instance = TestInstance(
                test_run_id=test_run.id,
                device_id=test.devicehostname_id,
                test_type="traceroute_test",
                traceroute_test_id=test.id
            )
            test_instances.append(instance)

        db.session.bulk_save_objects(test_instances)
        db.session.commit()

        run_tests_in_background(test_run.id)
        return redirect(url_for('test_progress', run_id=test_run.id))
    return render_template('start_test_run.html', form=form)  # Pass form to template
    
def run_tests_in_background(test_run_id):
    def worker(queue):
        while True:
            try:
                device_id = queue.get_nowait()
            except Queue.Empty:
                break
            run_tests_for_device(device_id, test_run_id, socketio)
            queue.task_done()

    # Get unique devices from this test run
    test_instances = TestInstance.query.filter_by(test_run_id=test_run_id).all()
    unique_device_ids = set(t.device_id for t in test_instances)

    # Create a queue and add devices
    device_queue = Queue()
    for device_id in unique_device_ids:
        device_queue.put(device_id)

    # Start up to 3 worker threads
    threads = []
    for _ in range(min(3, len(unique_device_ids))):
        t = Thread(target=worker, args=(device_queue,))
        t.start()
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()

def run_tests_for_device(device_id, test_run_id, socketio):
    device = Device.query.get(device_id)
    cred = DeviceCredential.query.get(device.username_id)
    conn_params = {
        "device_type": "cisco_ios",  # Adjust as needed
        "host": device.device_mgmtip,
        "username": cred.uname,
        "password": cred.pw,
        "timeout": 10,
        "session_timeout": 60,
    }

    socketio.emit('status_update', {'message': f"Connecting to device {device.devicehostname} ({device.device_mgmtip})", 'run_id': test_run_id})
    try:
        # Connect to device
        with netmiko.ConnectHandler(**conn_params) as conn:
            socketio.emit('status_update', {'message': f"Connected to device {device.devicehostname}", 'run_id': test_run_id})
            # Get tests for this device in this run
            tests = TestInstance.query.filter_by(test_run_id=test_run_id, device_id=device_id).all()
            for test in tests:
                test.status = "running"
                db.session.commit()
                socketio.emit('status_update', {'message': f"Running {test.test_type} test ID {test.id} on {device.devicehostname}", 'run_id': test_run_id})

                try:
                    
                    if test.test_type == "bgp_as_path":
                        bgp_test = test.bgp_as_path_test
                        output = conn.send_command("show ip bgp")  # Your Netmiko code
                        passed = check_bgp_result(output, bgp_test.checkASinpath, bgp_test.checkASwantresult)
                        result = bgpASpathTestResult(test_instance_id=test.id, output=output, passed=passed)
                        db.session.add(result)
                        socketio.emit('status_update', {'message': f"BGP test ID {test.id} completed on {device.devicehostname}", 'run_id': test_run_id})
                        
                    elif test.test_type == "traceroute_test":
                        traceroute_test = test.traceroute_test
                        output = conn.send_command(f"traceroute {traceroute_test.destinationip}")  # Your traceroute code
                        hop_count = count_hops(output)  # Example parsing function
                        result = tracerouteTestResult(test_instance_id=test.id, output=output, hop_count=hop_count)
                        db.session.add(result)
                        socketio.emit('status_update', {'message': f"Traceroute test ID {test.id} completed on {device.devicehostname}", 'run_id': test_run_id})
                    
                    test.status = "completed"
                
                except NetmikoTimeoutException as e:
                    logger.error(f"Timeout during test on {device.devicehostname}: {str(e)}")
                    socketio.emit('status_update', {'message': f"Timeout during test on {device.devicehostname}", 'run_id': test_run_id})
                    test.status = "failed"
                    result = (bgpASpathTestResult if test.test_type == "bgp_as_path" else tracerouteTestResult)(
                        test_instance_id=test.id, output=f"Error: {str(e)}", passed=False if test.test_type == "bgp_as_path" else None, hop_count=None
                    )
                    db.session.add(result)
                    
                except Exception as e:
                    logger.error(f"Unexpected error during test on {device.devicehostname}: {str(e)}")
                    socketio.emit('status_update', {'message': f"Error during test on {device.devicehostname}: {str(e)}", 'run_id': test_run_id})
                    test.status = "failed"
                    result = (bgpASpathTestResult if test.test_type == "bgp_as_path" else tracerouteTestResult)(
                        test_instance_id=test.id, output=f"Error: {str(e)}", passed=False if test.test_type == "bgp_as_path" else None, hop_count=None
                    )
                    db.session.add(result) 
                            
                db.session.commit()
                
    except NetmikoTimeoutException:
        logger.error(f"Device {device.devicehostname} unreachable (timeout)")
        socketio.emit('status_update', {'message': f"Device {device.devicehostname} unreachable (timeout)", 'run_id': test_run_id})
        skip_tests_for_device(device_id, test_run_id, "Unreachable: Timeout", socketio)
    except NetmikoAuthenticationException:
        logger.error(f"Authentication failed for {device.devicehostname}")
        socketio.emit('status_update', {'message': f"Authentication failed for {device.devicehostname}", 'run_id': test_run_id})
        skip_tests_for_device(device_id, test_run_id, "Authentication failed", socketio)
    except Exception as e:
        logger.error(f"Unexpected error connecting to {device.devicehostname}: {str(e)}")
        socketio.emit('status_update', {'message': f"Error connecting to {device.devicehostname}: {str(e)}", 'run_id': test_run_id})
        skip_tests_for_device(device_id, test_run_id, f"Error: {str(e)}", socketio)
    

def skip_tests_for_device(device_id, test_run_id, reason, socketio):
    tests = TestInstance.query.filter_by(test_run_id=test_run_id, device_id=device_id).all()
    for test in tests:
        if test.status == "pending":
            test.status = "skipped"
            result = (bgpASpathTestResult if test.test_type == "bgp_as_path" else tracerouteTestResult)(
                test_instance_id=test.id, output=f"Skipped: {reason}", passed=None, hop_count=None
            )
            db.session.add(result)
            socketio.emit('status_update', {'message': f"Skipped {test.test_type} test on device ID {device_id}: {reason}", 'run_id': test_run_id})
    db.session.commit()

def check_bgp_result(output, as_number, want_result):
    # Your logic to parse output and check if as_number appears as expected
    return as_number in output  # Simplified example

def count_hops(output):
    # Parse traceroute output to count hops (example)
    return len([line for line in output.splitlines() if line.strip().startswith(tuple(str(i) for i in range(1, 31)))])
    
if __name__ == '__main__':
    socketio.run(app, debug=True)
    