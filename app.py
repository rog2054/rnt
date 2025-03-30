from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_socketio import SocketIO
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from threading import Thread
import queue
from queue import Queue
from time import sleep  # Simulated test execution
from models import db, DeviceCredential, Device, bgpaspathTest, tracerouteTest, TestRun, TestInstance, bgpaspathTestResult, tracerouteTestResult
from forms import DeviceForm, CredentialForm, bgpaspathTestForm, tracerouteTestForm, TestRunForm
import netmiko
from netmiko import NetmikoTimeoutException, NetmikoAuthenticationException
import logging

# Globals
pending_test_runs = []
processed_devices = set() # Used for tracking processed devices per run

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define global extensions
socketio = SocketIO(async_mode='threading')


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///config.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'your-secret-key'

    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)
    socketio.init_app(app)

    with app.app_context():
        db.create_all()

    # Define routes
    @app.route('/tests/progress/<int:run_id>')
    def test_progress(run_id):
        test_run = TestRun.query.get_or_404(run_id)
        instances = TestInstance.query.filter_by(test_run_id=run_id).all()
        stats = {
            "bgpaspath_test": {"completed": 0, "running": 0, "skipped": 0, "total": 0},
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
        if form.validate_on_submit():
            test_run = TestRun(description=form.description.data, status="pending")  # Start as pending
            db.session.add(test_run)
            db.session.commit()

            test_instances = []
            bgp_tests = bgpaspathTest.query.all()
            for test in bgp_tests:
                instance = TestInstance(
                    test_run_id=test_run.id,
                    device_id=test.devicehostname_id,
                    test_type="bgpaspath_test",
                    bgpaspath_test_id=test.id
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

            # Queue the test run instead of starting it
            pending_test_runs.append(test_run.id)
            return redirect(url_for('test_progress', run_id=test_run.id))
        return render_template('start_test_run.html', form=form)

    @app.route('/credentials', methods=['GET', 'POST'])
    def credentials():
        form = CredentialForm()
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            is_passwordexpiry = 'passwordexpiry' in request.form
            new_credential = DeviceCredential(
                username=username, password=password, passwordexpiry=is_passwordexpiry)
            db.session.add(new_credential)
            db.session.commit()
            return jsonify({'message': 'User added'})
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
        devices = Device.query.all()
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
                        hostname=form.hostname.data,
                        mgmtip=form.mgmtip.data,
                        devicetype=form.devicetype.data, #dropdown
                        username_id=form.username.data, #dropdown
                        siteinfo=form.siteinfo.data,
                        lanip=form.lanip.data,
                        numerictraceroute=form.numerictraceroute.data
                    )
                    db.session.add(new_device)
                    db.session.commit()
                    # Redirect back to device list
                    return jsonify({'redirect': url_for('device_list')})
                except Exception as e:
                    db.session.rollback()  # In case of any error, rollback the session
                    print("Error adding device:", str(e))
                    return jsonify({'message': 'Database error: ' + str(e)}), 500
            # If form validation fails, return specific errors
            error_messages = {field: error for field,
                              error in form.errors.items()}
            return jsonify({'message': 'Form validation failed', 'errors': error_messages}), 400
        # If GET request, render form
        return render_template("add_device.html", form=form)

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
        bgpaspathtests = bgpaspathTest.query.all()
        return render_template('bgpaspathtests.html', bgpaspathtests=bgpaspathtests)

    # Add AS-path test
    @app.route('/tests/addtest_bgpaspath', methods=['GET', 'POST'])
    def addtest_bgpaspath():
        form = bgpaspathTestForm()
        if request.method == 'POST':
            if form.validate_on_submit():  # Form validation
                try:
                    # Create a new bgp as-path test using the form data
                    new_test = bgpaspathTest(
                        devicehostname_id=form.test_device_hostname.data,
                        testipv4prefix=form.test_ipv4prefix.data,
                        checkasinpath=form.test_checkasinpath.data,
                        checkaswantresult=form.test_checkaswantresult.data,
                        description=form.test_description.data
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
            error_messages = {field: error for field,
                              error in form.errors.items()}
            return jsonify({'message': 'Form validation failed', 'errors': error_messages}), 400
        # If GET request, render form
        return render_template("addtest_bgpaspath.html", form=form)

    # Delete AS-path Test
    @app.route('/tests/delete_bgpaspathtest/<int:test_id>', methods=['POST'])
    def delete_bgptest(test_id):
        test = bgpaspathTest.query.get_or_404(test_id)
        db.session.delete(test)
        db.session.commit()
        return jsonify({'message': 'BGP AS-path Test removed successfully'})

    # Display all Traceroute Tests
    @app.route('/tests/traceroute', methods=['GET'])
    def showtests_traceroute():
        traceroutetests = tracerouteTest.query.all()
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
                        description=form.test_description.data
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
            error_messages = {field: error for field,
                              error in form.errors.items()}
            return jsonify({'message': 'Form validation failed', 'errors': error_messages}), 400
        # If GET request, render form
        return render_template("addtest_traceroute.html", form=form)

    # Delete Traceroute Test
    @app.route('/tests/delete_traceroutetest/<int:test_id>', methods=['POST'])
    def delete_traceroutetest(test_id):
        test = tracerouteTest.query.get_or_404(test_id)
        db.session.delete(test)
        db.session.commit()
        return jsonify({'message': 'Traceroute Test removed successfully'})

    # Add other routes here if needed
    
    # Add Socket.IO handler
    @socketio.on('start_tests')
    def handle_start_tests(data):
        run_id = data.get('run_id')
        logger.info(f"Starting tests for run ID {run_id} via Socket.IO")
        if run_id in pending_test_runs:
            with app.app_context():
                test_run = db.session.get(TestRun, run_id)
                test_run.status = "running"
                db.session.commit()
            processed_devices.clear()  # Reset for new run
            pending_test_runs.remove(run_id)  # Dequeue the run
            socketio.start_background_task(run_tests_in_background, run_id)
        else:
            logger.debug(f"Test run {run_id} not in pending_test_runs, ignoring")
        
    return app


app = create_app()
CSRFProtect(app)

# Background Routes


def run_tests_in_background(test_run_id):
    def worker(device_queue):
        with app.app_context():
            while True:
                try:
                    device_id = device_queue.get_nowait()
                    logger.info(f"Worker picked up device ID: {device_id} for run ID: {test_run_id}")
                except queue.Empty:
                    logger.info(f"Queue empty, worker exiting for run ID: {test_run_id}")
                    break
                run_tests_for_device(device_id, test_run_id)
                processed_devices.add((test_run_id, device_id))
                device_queue.task_done()

    with app.app_context():
        logger.info(f"Starting background tests for run ID: {test_run_id}")
        test_instances = TestInstance.query.filter_by(test_run_id=test_run_id).all()
        unique_device_ids = set(t.device_id for t in test_instances)
        logger.info(f"Unique DeviceIDs for run ID {test_run_id}: {unique_device_ids}")

        device_queue = Queue()
        for device_id in unique_device_ids:
            logger.debug(f"Queuing device_id: {device_id}, queue size: {device_queue.qsize()}")
            device_queue.put(device_id)
            logger.debug(f"Queued device ID: {device_id} for run ID: {test_run_id}")

        threads = []
        for _ in range(min(3, len(unique_device_ids))):
            t = Thread(target=worker, args=(device_queue,))
            t.start()
            threads.append(t)
            logger.debug(f"Started thread for run ID: {test_run_id}")

        for t in threads:
            t.join()
        logger.info(f"All threads completed for run ID: {test_run_id}")
        socketio.emit('status_update', {'message': f"Test run {test_run_id} completed", 'run_id': test_run_id, 'level': 'parent'})

def run_tests_for_device(device_id, test_run_id):
    def emit_stats_update():
        """Helper to emit current stats for the test run."""
        instances = TestInstance.query.filter_by(test_run_id=test_run_id).all()
        stats = {
            "bgpaspath_test": {"completed": 0, "running": 0, "skipped": 0, "total": 0},
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
        socketio.emit('stats_update', {'stats': stats, 'run_id': test_run_id})
        logger.info(f"socketio.emit: stats_update with {stats}")

    with app.app_context():
        device = db.session.get(Device, device_id)
        cred = db.session.get(DeviceCredential, device.username_id)
        if cred is None:
            logger.error(f"No credentials found for device {device.hostname}")
            socketio.emit('status_update', {'message': f"No credentials for {device.hostname}", 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
            skip_tests_for_device(device_id, test_run_id, "No credentials")
            emit_stats_update()
            return

        conn_params = {
            "device_type": "cisco_ios",
            "host": device.mgmtip,
            "username": cred.username,
            "password": cred.password,
            "timeout": 10,
            "session_timeout": 60,
        }

        logger.debug(f"Starting run_tests_for_device for device_id: {device_id}, run_id: {test_run_id}")
        socketio.emit('status_update', {'message': f"Connecting to device {device.hostname} ({device.mgmtip})", 'run_id': test_run_id, 'level': 'parent', 'device_id': device_id})
        logger.info(f"socketio.emit: 'Connecting to device {device.hostname} ({device.mgmtip})' for run_id: {test_run_id}")

        try:
            with netmiko.ConnectHandler(**conn_params) as conn:
                socketio.emit('status_update', {'message': f"Connected to device {device.hostname}", 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
                logger.info(f"socketio.emit: 'Connected to device {device.hostname}' for run_id: {test_run_id}")
                tests = TestInstance.query.filter_by(test_run_id=test_run_id, device_id=device_id).all()
                for test in tests:
                    test.status = "running"
                    db.session.commit()
                    socketio.emit('status_update', {'message': f"Running {test.test_type} test ID {test.id} on {device.hostname}", 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
                    logger.info(f"socketio.emit: 'Running {test.test_type} test ID {test.id}' for run_id: {test_run_id}")
                    emit_stats_update()
                    try:
                        if test.test_type == "bgpaspath_test":
                            bgp_test = test.bgp_as_path_test
                            rawoutput = conn.send_command("show ip bgp")
                            passed = check_bgp_result(rawoutput, bgp_test.checkasinpath, bgp_test.checkaswantresult)
                            result = bgpaspathTestResult(test_instance_id=test.id, rawoutput=rawoutput, passed=passed)
                            db.session.add(result)
                            socketio.emit('status_update', {'message': f"BGP test ID {test.id} completed on {device.hostname}", 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
                            logger.info(f"socketio.emit: 'BGP test ID {test.id} completed' for run_id: {test_run_id}")
                        elif test.test_type == "traceroute_test":
                            traceroute_test = test.traceroute_test
                            rawoutput = conn.send_command(f"traceroute {traceroute_test.destinationip}")
                            numberofhops = count_hops(rawoutput)
                            result = tracerouteTestResult(test_instance_id=test.id, rawoutput=rawoutput, numberofhops=numberofhops)
                            db.session.add(result)
                            socketio.emit('status_update', {'message': f"Traceroute test ID {test.id} completed on {device.hostname}", 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
                            logger.info(f"socketio.emit: 'Traceroute test ID {test.id} completed' for run_id: {test_run_id}")
                        test.status = "completed"
                    except NetmikoTimeoutException as e:
                        logger.error(f"Timeout during test on {device.hostname}: {str(e)}")
                        socketio.emit('status_update', {'message': f"Timeout during test on {device.hostname}", 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
                        test.status = "failed"
                        result = (bgpaspathTestResult if test.test_type == "bgpaspath_test" else tracerouteTestResult)(
                            test_instance_id=test.id, rawoutput=f"Error: {str(e)}", passed=False if test.test_type == "bgpaspath_test" else None, numberofhops=None
                        )
                        db.session.add(result)
                    except Exception as e:
                        logger.error(f"Unexpected error during test on {device.hostname}: {str(e)}")
                        socketio.emit('status_update', {'message': f"Error during test on {device.hostname}: {str(e)}", 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
                        test.status = "failed"
                        result = (bgpaspathTestResult if test.test_type == "bgpaspath_test" else tracerouteTestResult)(
                            test_instance_id=test.id, rawoutput=f"Error: {str(e)}", passed=False if test.test_type == "bgpaspath_test" else None, numberofhops=None
                        )
                        db.session.add(result)
                    db.session.commit()
                    emit_stats_update()

        except NetmikoTimeoutException:
            logger.error(f"Device {device.hostname} unreachable (timeout)")
            socketio.emit('status_update', {'message': f"Device {device.hostname} unreachable (timeout)", 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
            skip_tests_for_device(device_id, test_run_id, "Unreachable: Timeout")
            emit_stats_update()
        except NetmikoAuthenticationException:
            logger.error(f"Authentication failed for {device.hostname}")
            socketio.emit('status_update', {'message': f"Authentication failed for {device.hostname}", 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
            skip_tests_for_device(device_id, test_run_id, "Authentication failed")
            emit_stats_update()
        except Exception as e:
            logger.error(f"Unexpected error connecting to {device.hostname}: {str(e)}")
            socketio.emit('status_update', {'message': f"Error connecting to {device.hostname}: {str(e)}", 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
            skip_tests_for_device(device_id, test_run_id, f"Error: {str(e)}")
            emit_stats_update()

def skip_tests_for_device(device_id, test_run_id, reason):
    with app.app_context():
        tests = TestInstance.query.filter_by(test_run_id=test_run_id, device_id=device_id).all()
        device = db.session.get(Device, device_id)
        if not tests or (test_run_id, device_id) in processed_devices:
            return # Skip if already processed

        # Count test types
        bgp_count = sum(1 for t in tests if t.test_type == "bgpaspath_test")
        traceroute_count = sum(1 for t in tests if t.test_type == "traceroute_test")
        skip_summary = []
        if bgp_count:
            skip_summary.append(f"{bgp_count} BGP test{'s' if bgp_count > 1 else ''}")
        if traceroute_count:
            skip_summary.append(f"{traceroute_count} Traceroute test{'s' if traceroute_count > 1 else ''}")
        summary_msg = f"Skipping {', '.join(skip_summary)} for device {device.hostname}: {reason}"

        # Skip all tests at once
        for test in tests:
            if test.status == "pending":
                test.status = "skipped"
        db.session.commit()

        socketio.emit('status_update', {
            'message': summary_msg,
            'run_id': test_run_id,
            'level': 'child',
            'device_id': device_id
        })
        logger.info(f"socketio.emit: '{summary_msg}' for run_id: {test_run_id}")


def check_bgp_result(output, as_number, want_result):
    # Your logic to parse output and check if as_number appears as expected
    return as_number in output  # Simplified example


def count_hops(output):
    # Parse traceroute output to count hops (example)
    return len([line for line in output.splitlines() if line.strip().startswith(tuple(str(i) for i in range(1, 31)))])


if __name__ == '__main__':
    socketio.run(app, debug=True)
