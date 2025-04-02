from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_socketio import SocketIO
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from threading import Thread
import threading
import queue
from queue import Queue
from models import db, DeviceCredential, Device, bgpaspathTest, tracerouteTest, TestRun, TestInstance, bgpaspathTestResult, tracerouteTestResult
from forms import DeviceForm, CredentialForm, bgpaspathTestForm, tracerouteTestForm, TestRunForm
import netmiko
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import logging
import re
from datetime import datetime, timezone

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

    @app.route('/toggle_device_active/<int:device_id>', methods=['POST'])
    def toggle_device_active(device_id):
        device = Device.query.get_or_404(device_id)
        new_active = request.form.get('active') == 'true'  # Convert string 'true'/'false' to boolean
        device.active = new_active
        db.session.commit()
        return jsonify({'message': f'Device {device.hostname} {"enabled" if new_active else "disabled"} successfully'})

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

    # Detail tables showing the results of a specific batch of tests
    @app.route('/test_results/<int:run_id>')
    def test_results(run_id):
        with app.app_context():
            # Fetch BGP test results
            bgp_results = db.session.query(TestInstance, bgpaspathTestResult, Device, bgpaspathTest)\
                .join(bgpaspathTestResult, TestInstance.id == bgpaspathTestResult.test_instance_id)\
                .join(Device, TestInstance.device_id == Device.id)\
                .join(bgpaspathTest, TestInstance.bgpaspath_test_id == bgpaspathTest.id)\
                .filter(TestInstance.test_run_id == run_id, TestInstance.test_type == "bgpaspath_test")\
                .all()

            # Fetch Traceroute test results
            traceroute_results = db.session.query(TestInstance, tracerouteTestResult, Device, tracerouteTest)\
                .join(tracerouteTestResult, TestInstance.id == tracerouteTestResult.test_instance_id)\
                .join(Device, TestInstance.device_id == Device.id)\
                .join(tracerouteTest, TestInstance.traceroute_test_id == tracerouteTest.id)\
                .filter(TestInstance.test_run_id == run_id, TestInstance.test_type == "traceroute_test")\
                .all()

            # Fetch the test run timestamp (assuming TestInstance has a timestamp field)
            test_instance = db.session.query(TestInstance).filter_by(test_run_id=run_id).first()
            run_timestamp = test_instance.test_run.start_time if test_instance else None
            run_endtimestamp = test_instance.test_run.end_time if test_instance else None

            testrun = db.session.query(TestRun).filter_by(id=run_id).first()
            run_description = testrun.description if testrun else run_id
            
            test_run = db.session.query(TestRun).filter_by(id=run_id).first()
            run_log = test_run.log if test_run.log else "No log available"
            
            # Debug logging
            logger.info(f"BGP Results: {len(bgp_results)} entries")
            for ti, result, dev, test in bgp_results:
                logger.info(f"BGP - Device: {dev.hostname}, Active: {ti.device_active_at_run}, Passed: {result.passed}")
            logger.info(f"Traceroute Results: {len(traceroute_results)} entries")
            for ti, result, dev, test in traceroute_results:
                logger.info(f"Traceroute - Device: {dev.hostname}, Active: {ti.device_active_at_run}, Passed: {result.passed}")

            # Calculate summary counts
            # Calculate BGP summary
            bgp_pass = sum(1 for _, result, _, _ in bgp_results if result.passed)
            bgp_fail = sum(1 for _, result, _, _ in bgp_results if result.passed is False)
            bgp_skipped_inactive = sum(1 for ti, result, _, _ in bgp_results if not ti.device_active_at_run)
            bgp_skipped_error = sum(1 for ti, result, _, _ in bgp_results if result.passed is None and ti.device_active_at_run)

            # Calculate Traceroute summary
            traceroute_pass = sum(1 for _, result, _, _ in traceroute_results if result.passed)
            traceroute_fail = sum(1 for _, result, _, _ in traceroute_results if result.passed is False)
            traceroute_skipped_inactive = sum(1 for ti, result, _, _ in traceroute_results if not ti.device_active_at_run)
            traceroute_skipped_error = sum(1 for ti, result, _, _ in traceroute_results if result.passed is None and ti.device_active_at_run)

            all_bgp_tests_passed = True if bgp_fail == 0 else False
            all_traceroute_tests_passed = True if traceroute_fail == 0 else False

            # More debug logging
            logger.info(f"BGP: Pass={bgp_pass}, Fail={bgp_fail}, Skipped Inactive={bgp_skipped_inactive}, Skipped Error={bgp_skipped_error}")
            logger.info(f"Traceroute: Pass={traceroute_pass}, Fail={traceroute_fail}, Skipped Inactive={traceroute_skipped_inactive}, Skipped Error={traceroute_skipped_error}")

        return render_template('test_results.html', 
                            run_id=run_id, 
                            bgp_results=bgp_results, 
                            traceroute_results=traceroute_results,
                            run_timestamp=run_timestamp,
                            run_endtimestamp=run_endtimestamp,
                            run_description=run_description,
                            bgp_pass=bgp_pass, bgp_fail=bgp_fail,
                            bgp_skipped_inactive=bgp_skipped_inactive, bgp_skipped_error=bgp_skipped_error,
                            traceroute_pass=traceroute_pass, traceroute_fail=traceroute_fail,
                            traceroute_skipped_inactive=traceroute_skipped_inactive, 
                            traceroute_skipped_error=traceroute_skipped_error,
                            all_bgp_tests_passed=all_bgp_tests_passed, all_traceroute_tests_passed=all_traceroute_tests_passed,
                            run_log=run_log)
        

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
    def worker(device_queue, log_lines, log_lock):
        with app.app_context():
            while True:
                try:
                    device_id = device_queue.get_nowait()
                    logger.info(f"Worker picked up device ID: {device_id} for run ID: {test_run_id}")
                except queue.Empty:
                    logger.info(f"Queue empty, worker exiting for run ID: {test_run_id}")
                    break
                run_tests_for_device(device_id, test_run_id, log_lines, log_lock)
                processed_devices.add((test_run_id, device_id))
                device_queue.task_done()

    with app.app_context():
        logger.info(f"Starting background tests for run ID: {test_run_id}")
        test_instances = TestInstance.query.filter_by(test_run_id=test_run_id).all()
        unique_device_ids = set(t.device_id for t in test_instances)
        logger.info(f"Unique DeviceIDs for run ID {test_run_id}: {unique_device_ids}")

        # Initialize log buffer and lock
        log_lines = [f"Starting test run {test_run_id} at {db.session.get(TestRun,test_run_id).start_time.strftime('%Y-%m-%d %H:%M:%S')}"]
        log_lock = threading.Lock()

        device_queue = Queue()
        for device_id in unique_device_ids:
            logger.debug(f"Queuing device_id: {device_id}, queue size: {device_queue.qsize()}")
            device_queue.put(device_id)
            logger.debug(f"Queued device ID: {device_id} for run ID: {test_run_id}")

        threads = []
        for _ in range(min(3, len(unique_device_ids))):
            t = Thread(target=worker, args=(device_queue, log_lines, log_lock))
            t.start()
            threads.append(t)
            logger.debug(f"Started thread for run ID: {test_run_id}")

        for t in threads:
            t.join()
        logger.info(f"All threads completed for run ID: {test_run_id}")

        test_run = db.session.get(TestRun, test_run_id)
        timenow = datetime.now(timezone.utc)
        with log_lock:
            log_msg = (f"Ending test run {test_run_id} at {timenow.strftime('%Y-%m-%d %H:%M:%S')}")
            log_lines.append(log_msg)
            test_run.log = "\n".join(log_lines)
        test_run.status = "completed"
        test_run.end_time = timenow
        db.session.commit()
        
        socketio.emit('status_update', {'message': f"Test run {test_run_id} completed at {timenow.strftime('%Y-%m-%d %H:%M:%S')}", 'run_id': test_run_id, 'level': 'parent'})
        

def run_tests_for_device(device_id, test_run_id, log_lines, log_lock):
    def emit_stats_update():
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

        # Log and skip if device is disabled
        if not device.active:
            log_msg = f"Device {device.hostname}: Skipped (Disabled in app)"
            with log_lock:
                log_lines.append(log_msg)
            socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'parent', 'device_id': device_id})
            skip_tests_for_device(device_id, test_run_id, "Device disabled in app", log_lines, log_lock)
            # Set the Active flag to False for every test for this device, as we have identified the device is disabled in the app settings.
            tests = TestInstance.query.filter_by(test_run_id=test_run_id, device_id=device_id).all()
            for test in tests:
                test.device_active_at_run = False
            db.session.commit()
            emit_stats_update()
            return

        if cred is None:
            log_msg = f"Device {device.hostname}: Skipped (No credentials)"
            with log_lock:
                log_lines.append(log_msg)
            socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
            skip_tests_for_device(device_id, test_run_id, "No credentials", log_lines, log_lock)
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

        log_msg = f"Device {device.hostname}: Connecting to {device.mgmtip}"
        with log_lock:
            log_lines.append(log_msg)
        socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'parent', 'device_id': device_id})
        logger.info(f"socketio.emit: '{log_msg}' for run_id: {test_run_id}")

        try:
            with ConnectHandler(**conn_params) as conn:
                log_msg = f"Device {device.hostname}: Connected"
                with log_lock:
                    log_lines.append(log_msg)
                socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
                logger.info(f"socketio.emit: '{log_msg}' for run_id: {test_run_id}")

                tests = TestInstance.query.filter_by(test_run_id=test_run_id, device_id=device_id).all()
                for test in tests:
                    test.status = "running"
                    db.session.commit()
                    log_msg = f"Device {device.hostname}: Running {test.test_type} test ID {test.id}"
                    with log_lock:
                        log_lines.append(log_msg)
                    socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
                    logger.info(f"socketio.emit: '{log_msg}' for run_id: {test_run_id}")
                    emit_stats_update()

                    try:
                        if test.test_type == "bgpaspath_test":
                            bgp_test = test.bgpaspath_test
                            rawoutput = conn.send_command(f"show ip bgp {bgp_test.testipv4prefix} bestpath")
                            pattern = r"Refresh Epoch (\d+)\n(.*)"
                            pattern2 = r"Network not in table"
                            match = re.search(pattern, rawoutput)
                            if match:
                                output = match.group(2).strip()
                                if len(output) > 3:
                                    if bgp_test.checkasinpath in output:
                                        passed = bgp_test.checkaswantresult
                                    else:
                                        passed = not bgp_test.checkaswantresult
                            else:
                                match2 = re.search(pattern2, rawoutput)
                                if match2:
                                    output = f"Prefix {bgp_test.testipv4prefix} not in bgp table"
                                    passed = False
                                else:
                                    output = "Unable to process the output, review raw output manually"
                                    passed = False
                            result = bgpaspathTestResult(test_instance_id=test.id, rawoutput=rawoutput, output=output, passed=passed)
                            db.session.add(result)
                            log_msg = f"Device {device.hostname}: BGP test ID {test.id} completed - {'Passed' if passed else 'Failed'}"
                            with log_lock:
                                log_lines.append(log_msg)
                            socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})

                        elif test.test_type == "traceroute_test":
                            traceroute_test = test.traceroute_test
                            if device.devicetype == "cisco_ios":
                                rawoutput = conn.send_command_timing(f"traceroute {traceroute_test.destinationip} source {device.lanip} numeric")
                            elif device.devicetype == "cisco_nxos":
                                rawoutput = conn.send_command_timing(f"traceroute {traceroute_test.destinationip} source {device.lanip}")
                            numberofhops = count_hops(rawoutput)
                            passed = numberofhops > 3
                            result = tracerouteTestResult(test_instance_id=test.id, rawoutput=rawoutput, numberofhops=numberofhops, passed=passed)
                            db.session.add(result)
                            log_msg = f"Device {device.hostname}: Traceroute test ID {test.id} completed - {'Passed' if passed else 'Failed'}"
                            with log_lock:
                                log_lines.append(log_msg)
                            socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})

                        test.status = "completed"

                    except NetmikoTimeoutException as e:
                        log_msg = f"Device {device.hostname}: Timeout during test - {str(e)}"
                        with log_lock:
                            log_lines.append(log_msg)
                        socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
                        test.status = "failed"
                        result = (bgpaspathTestResult if test.test_type == "bgpaspath_test" else tracerouteTestResult)(
                            test_instance_id=test.id, rawoutput=f"Error: {str(e)}", passed=False if test.test_type == "bgpaspath_test" else None, numberofhops=None
                        )
                        db.session.add(result)
                    except Exception as e:
                        log_msg = f"Device {device.hostname}: Error during test - {str(e)}"
                        with log_lock:
                            log_lines.append(log_msg)
                        socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
                        test.status = "failed"
                        result = (bgpaspathTestResult if test.test_type == "bgpaspath_test" else tracerouteTestResult)(
                            test_instance_id=test.id, rawoutput=f"Error: {str(e)}", passed=False if test.test_type == "bgpaspath_test" else None, numberofhops=None
                        )
                        db.session.add(result)
                    db.session.commit()
                    emit_stats_update()

        except NetmikoTimeoutException:
            log_msg = f"Device {device.hostname}: Unreachable (timeout)"
            with log_lock:
                log_lines.append(log_msg)
            socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
            skip_tests_for_device(device_id, test_run_id, "Unreachable: Timeout", log_lines, log_lock)
            emit_stats_update()
        except NetmikoAuthenticationException:
            log_msg = f"Device {device.hostname}: Authentication failed"
            with log_lock:
                log_lines.append(log_msg)
            socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
            skip_tests_for_device(device_id, test_run_id, "Authentication failed", log_lines, log_lock)
            emit_stats_update()
        except Exception as e:
            log_msg = f"Device {device.hostname}: Error connecting - {str(e)}"
            with log_lock:
                log_lines.append(log_msg)
            socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})
            skip_tests_for_device(device_id, test_run_id, f"Error: {str(e)}", log_lines, log_lock)
            emit_stats_update()

def skip_tests_for_device(device_id, test_run_id, reason, log_lines, log_lock):
    with app.app_context():
        tests = TestInstance.query.filter_by(test_run_id=test_run_id, device_id=device_id).all()
        device = db.session.get(Device, device_id)
        if not tests or (test_run_id, device_id) in processed_devices:
            return

        bgp_count = sum(1 for t in tests if t.test_type == "bgpaspath_test")
        traceroute_count = sum(1 for t in tests if t.test_type == "traceroute_test")
        skip_summary = []
        if bgp_count:
            skip_summary.append(f"{bgp_count} BGP test{'s' if bgp_count > 1 else ''}")
        if traceroute_count:
            skip_summary.append(f"{traceroute_count} Traceroute test{'s' if traceroute_count > 1 else ''}")
        summary_msg = f"Device {device.hostname}: Skipping {', '.join(skip_summary)} - {reason}"

        for test in tests:
            if test.status == "pending":
                test.status = "skipped"
                if test.test_type == "bgpaspath_test":
                    result = bgpaspathTestResult(test_instance_id=test.id, rawoutput=reason, passed=None)
                    db.session.add(result)
                elif test.test_type == "traceroute_test":
                    result = tracerouteTestResult(test_instance_id=test.id, rawoutput=reason, passed=None, numberofhops=None)
                    db.session.add(result)
        db.session.commit()

        with log_lock:
            log_lines.append(summary_msg)
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
