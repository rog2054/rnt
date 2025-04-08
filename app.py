from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from threading import Thread
import threading
import queue
from queue import Queue
from models import db, Device, bgpaspathTest, tracerouteTest, TestRun, TestInstance, bgpaspathTestResult, tracerouteTestResult, User
from forms import DeviceForm, CredentialForm, bgpaspathTestForm, tracerouteTestForm, TestRunForm, CreateUserForm, LoginForm
import netmiko
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import logging
import re
from datetime import datetime, timezone
import bcrypt
import os
from cryptography.fernet import Fernet

# Globals
pending_test_runs = []
processed_devices = set() # Used for tracking processed devices per run

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define global extensions
socketio = SocketIO(async_mode='threading')
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///config.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'gfd789ydfs2Anvjfkdgnfs38dKZKXsd83d'
    
    # setup encryption for safe storing of the device credentials within the db
    app.config['ENCRYPTION_KEY'] = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
    global cipher # define as global so it is accessible by the async functions also
    cipher = Fernet(app.config['ENCRYPTION_KEY'])
    from models import DeviceCredential
    
    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)
    socketio.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login' # redirect unauth users to login route

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    with app.app_context():
        db.create_all()

    # Check for no users before each request
    @app.before_request
    def check_initial_user():
        if request.endpoint not in ['login', 'create_user', 'static']:  # Allow these routes regardless
            with app.app_context():
                if User.query.count() == 0:
                    return redirect(url_for('create_user'))

    # Define routes
    @app.route('/')
    @login_required
    def index():
        try:
            with open('/app/version.txt', 'r') as f:
                version = f.read().strip()
        except FileNotFoundError:
            version = 'x'
        return f"<h1>Welcome, {current_user.username}!</h1><h2>Version: 0.{version}</h2><br /><a href='/devices'>Start</a>"
    
    '''
    @app.route('/')
    def index():
        # Read the version from the file
        try:
            with open('/app/version.txt', 'r') as f:
                version = f.read().strip()
        except FileNotFoundError:
            version = 'unknown'
        return render_template('index.html', version=version)
    '''
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        form = LoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('test_results', run_id=1))
            flash('Invalid username or password')
        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/create_user', methods=['GET', 'POST'])
    def create_user():
        user_count = User.query.count()
        form = CreateUserForm()  # Instantiate the form

        if user_count > 0 and not current_user.is_authenticated:
            flash('You must be logged in to create additional users.')
            return redirect(url_for('login'))

        if form.validate_on_submit():  # Handles POST with CSRF validation
            username = form.username.data
            password = form.password.data
            if User.query.filter_by(username=username).first():
                flash('Username already exists.')
            else:
                new_user = User(username=username)
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                if user_count == 0:
                    login_user(new_user)
                    return redirect(url_for('index'))
                flash('User created successfully.')
                return redirect(url_for('login'))
        return render_template('create_user.html', form=form, user_count=user_count)
    
    @app.route('/tests/progress/<int:run_id>')
    @login_required
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
    @login_required
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
    @login_required
    def credentials():
        form = CredentialForm()
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            is_passwordexpiry = 'passwordexpiry' in request.form
            new_credential = DeviceCredential(
                username=username, passwordexpiry=is_passwordexpiry)
            new_credential.set_password(password)  # Encrypt the password
            db.session.add(new_credential)
            db.session.commit()
            return jsonify({'message': 'User added'})
        credentials = DeviceCredential.query.all()
        return render_template('credentials.html', credentials=credentials, form=form)

    # Delete credential
    @app.route('/delete_credential/<int:credential_id>', methods=['POST'])
    @login_required
    def delete_credential(credential_id):
        credential = DeviceCredential.query.get_or_404(credential_id)
        db.session.delete(credential)
        db.session.commit()
        return jsonify({'message': 'Credential deleted successfully'})

    @app.route('/devices')
    @login_required
    def device_list():
        devices = Device.query.all()
        return render_template('devices.html', devices=devices)

    # Route to display the add device form
    @app.route('/devices/add', methods=['GET', 'POST'])
    @login_required
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
    @login_required
    def delete_device(device_id):
        device = Device.query.get_or_404(device_id)
        db.session.delete(device)
        db.session.commit()
        return jsonify({'message': 'Device removed successfully'})

    @app.route('/toggle_device_active/<int:device_id>', methods=['POST'])
    @login_required
    def toggle_device_active(device_id):
        device = Device.query.get_or_404(device_id)
        new_active = request.form.get('active') == 'true'  # Convert string 'true'/'false' to boolean
        device.active = new_active
        db.session.commit()
        return jsonify({'message': f'Device {device.hostname} {"enabled" if new_active else "disabled"} successfully'})

    # Display all AS-path tests
    @app.route('/tests/bgpaspath', methods=['GET'])
    @login_required
    def showtests_bgpaspath():
        bgpaspathtests = bgpaspathTest.query.all()
        return render_template('bgpaspathtests.html', bgpaspathtests=bgpaspathtests)

    # Add AS-path test
    @app.route('/tests/addtest_bgpaspath', methods=['GET', 'POST'])
    @login_required
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
    @login_required
    def delete_bgptest(test_id):
        test = bgpaspathTest.query.get_or_404(test_id)
        db.session.delete(test)
        db.session.commit()
        return jsonify({'message': 'BGP AS-path Test removed successfully'})

    # Display all Traceroute Tests
    @app.route('/tests/traceroute', methods=['GET'])
    @login_required
    def showtests_traceroute():
        traceroutetests = tracerouteTest.query.all()
        return render_template('traceroutetests.html', traceroutetests=traceroutetests)

    # Add Traceroute test
    @app.route('/tests/addtest_traceroute', methods=['GET', 'POST'])
    @login_required
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
    @login_required
    def delete_traceroutetest(test_id):
        test = tracerouteTest.query.get_or_404(test_id)
        db.session.delete(test)
        db.session.commit()
        return jsonify({'message': 'Traceroute Test removed successfully'})

    # Detail tables showing the results of a specific batch of tests
    @app.route('/test_results/<int:run_id>')
    @login_required
    def test_results(run_id):
        # Redirect to the same run_id but with '/pass' filter
        return redirect(url_for('test_results_filtered', run_id=run_id, filter_type='pass'))
    
    @app.route('/test_results/<int:run_id>/<filter_type>')
    @login_required
    def test_results_filtered(run_id, filter_type):
        valid_filters = ['pass', 'fail', 'incomplete', 'skipped']
        if filter_type not in valid_filters:
            return "Invalid filter type", 400

        with app.app_context():
            # Base queries for all results (unfiltered for totals)
            bgp_base_query = (db.session.query(TestInstance, bgpaspathTestResult, Device, bgpaspathTest)
                            .join(bgpaspathTestResult, TestInstance.id == bgpaspathTestResult.test_instance_id)
                            .join(Device, TestInstance.device_id == Device.id)
                            .join(bgpaspathTest, TestInstance.bgpaspath_test_id == bgpaspathTest.id)
                            .filter(TestInstance.test_run_id == run_id, TestInstance.test_type == "bgpaspath_test"))

            traceroute_base_query = (db.session.query(TestInstance, tracerouteTestResult, Device, tracerouteTest)
                                .join(tracerouteTestResult, TestInstance.id == tracerouteTestResult.test_instance_id)
                                .join(Device, TestInstance.device_id == Device.id)
                                .join(tracerouteTest, TestInstance.traceroute_test_id == tracerouteTest.id)
                                .filter(TestInstance.test_run_id == run_id, TestInstance.test_type == "traceroute_test"))

            # Calculate totals from unfiltered data
            bgp_totals = {
                'pass': sum(1 for _, r, _, _ in bgp_base_query.filter(bgpaspathTestResult.passed == True).all()),
                'fail': sum(1 for _, r, _, _ in bgp_base_query.filter(bgpaspathTestResult.passed == False).all()),
                'incomplete': sum(1 for ti, r, _, _ in bgp_base_query.filter(bgpaspathTestResult.passed == None, TestInstance.device_active_at_run == True).all()),
                'skipped': sum(1 for ti, _, _, _ in bgp_base_query.filter(TestInstance.device_active_at_run == False).all())
            }
            
            traceroute_totals = {
                'pass': sum(1 for _, r, _, _ in traceroute_base_query.filter(tracerouteTestResult.passed == True).all()),
                'fail': sum(1 for _, r, _, _ in traceroute_base_query.filter(tracerouteTestResult.passed == False).all()),
                'incomplete': sum(1 for ti, r, _, _ in traceroute_base_query.filter(tracerouteTestResult.passed == None, TestInstance.device_active_at_run == True).all()),
                'skipped': sum(1 for ti, _, _, _ in traceroute_base_query.filter(TestInstance.device_active_at_run == False).all())
            }

            totals = {
                'pass': bgp_totals['pass'] + traceroute_totals['pass'],
                'fail': bgp_totals['fail'] + traceroute_totals['fail'],
                'incomplete': bgp_totals['incomplete'] + traceroute_totals['incomplete'],
                'skipped': bgp_totals['skipped'] + traceroute_totals['skipped']
            }

            # Filtered queries for display
            bgp_query = bgp_base_query
            traceroute_query = traceroute_base_query

            # Apply filters to display results
            if filter_type == 'pass':
                bgp_query = bgp_query.filter(bgpaspathTestResult.passed == True)
                traceroute_query = traceroute_query.filter(tracerouteTestResult.passed == True)
            elif filter_type == 'fail':
                bgp_query = bgp_query.filter(bgpaspathTestResult.passed == False)
                traceroute_query = traceroute_query.filter(tracerouteTestResult.passed == False)
            elif filter_type == 'incomplete':
                bgp_query = bgp_query.filter(bgpaspathTestResult.passed == None, TestInstance.device_active_at_run == True)
                traceroute_query = traceroute_query.filter(tracerouteTestResult.passed == None, TestInstance.device_active_at_run == True)
            elif filter_type == 'skipped':
                bgp_query = bgp_query.filter(TestInstance.device_active_at_run == False)
                traceroute_query = traceroute_query.filter(TestInstance.device_active_at_run == False)

            bgp_results = bgp_query.all()
            traceroute_results = traceroute_query.all()

            # Fetch test run details
            test_instance = db.session.query(TestInstance).filter_by(test_run_id=run_id).first()
            run_timestamp = test_instance.test_run.start_time if test_instance else None
            run_endtimestamp = test_instance.test_run.end_time if test_instance else None

            test_run = db.session.query(TestRun).filter_by(id=run_id).first()
            if test_run:
                run_description = test_run.description
                run_log = test_run.log if test_run.log else "No log available"
            else:
                run_description = f"Run {run_id}"
                run_log = "No log available"

        return render_template('test_results_filtered.html',
                            run_id=run_id,
                            filter_type=filter_type,
                            bgp_results=bgp_results,
                            traceroute_results=traceroute_results,
                            run_timestamp=run_timestamp,
                            run_endtimestamp=run_endtimestamp,
                            run_description=run_description,
                            run_log=run_log,
                            totals=totals)

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

# Background Routes and Functions
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
        from models import DeviceCredential # lazy import
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
            "password": cred.get_password(),  # Decrypt the password
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
                                    # set to None so this shows as 'incomplete' in the UI rather than Failed
                                    # a Failed BGP test is where the target AS was/wasn't found in the AS path for the prefix
                                    passed = None
                                else:
                                    output = "Unable to process the output, review raw output manually"
                                    passed = False
                            result = bgpaspathTestResult(test_instance_id=test.id, rawoutput=rawoutput, output=output, passed=passed)
                            db.session.add(result)
                            if passed is None:
                                log_msg = f"Device {device.hostname}: BGP test ID {test.id} incomplete - Prefix not found"
                            else:
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
    # For local development only
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
