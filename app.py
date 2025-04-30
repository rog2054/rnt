from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from threading import Thread
import threading
import queue
from queue import Queue
from extensions import db, cipher
from models import Device, DeviceCredential, bgpaspathTest, tracerouteTest, TestRun, TestInstance, bgpaspathTestResult, tracerouteTestResult, User, txrxtransceiverTest, itracerouteTest, txrxtransceiverTestResult, itracerouteTestResult
from forms import DeviceForm, CredentialForm, bgpaspathTestForm, tracerouteTestForm, TestRunForm, CreateUserForm, LoginForm, txrxtransceiverTestForm, itracerouteTestForm, CompareTestRunsForm, ThemeForm, ChangePasswordForm
import netmiko
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import logging
import re
from datetime import datetime, timezone
from sqlalchemy import func
from utils import format_datetime_with_ordinal
from werkzeug.middleware.proxy_fix import ProxyFix
import os

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
    
    # Read version number at startup
    try:
        with open('/app/version.txt', 'r') as f:
            app.config['VERSION'] = f.read().strip()
    except FileNotFoundError:
        app.config['VERSION'] = 'x'
    
    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)
    socketio.init_app(app)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)
    login_manager.init_app(app)
    login_manager.login_view = 'login' # redirect unauth users to login route

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Configure Netmiko logger to write to /instance/netmiko_debug.log
    netmiko_logger = logging.getLogger("netmiko")
    netmiko_logger.setLevel(logging.DEBUG)
    log_file_path = os.path.join(app.instance_path, 'netmiko_debug.log')
    os.makedirs(app.instance_path, exist_ok=True)
    netmiko_handler = logging.FileHandler(log_file_path)
    netmiko_handler.setLevel(logging.DEBUG)
    netmiko_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    netmiko_handler.setFormatter(netmiko_formatter)
    if not netmiko_logger.handlers:
        netmiko_logger.addHandler(netmiko_handler)
    netmiko_logger.propagate = False

    with app.app_context():
        db.create_all()

    # Make version available to all templates
    @app.context_processor
    def inject_version():
        return dict(version=app.config['VERSION'])
    
    @app.context_processor
    def inject_user():
        return dict(user=current_user)

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
                if current_user.id:
                    new_user.created_by_id = current_user.id
                else:
                    # default to admin as creator if not logged in, as that means the admin is creating the initial user account
                    new_user.created_by_id = 1
                    new_user.theme = 'blue'
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
            "txrxtransceiver_test": {"completed": 0, "running": 0, "skipped": 0, "total": 0},
            "itraceroute_test": {"completed": 0, "running": 0, "skipped": 0, "total": 0},
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
            test_run.created_by_id = current_user.id
            db.session.add(test_run)
            db.session.commit()

            test_instances = []
            itraceroute_tests = itracerouteTest.query.filter_by(hidden=False).all()
            for test in itraceroute_tests:
                instance = TestInstance(
                    test_run_id=test_run.id,
                    device_id=test.devicehostname_id,
                    test_type="itraceroute_test",
                    itraceroute_test_id=test.id
                )
                test_instances.append(instance)
                
            traceroute_tests = tracerouteTest.query.filter_by(hidden=False).all()
            for test in traceroute_tests:
                instance = TestInstance(
                    test_run_id=test_run.id,
                    device_id=test.devicehostname_id,
                    test_type="traceroute_test",
                    traceroute_test_id=test.id
                )
                test_instances.append(instance)
                
            bgp_tests = bgpaspathTest.query.filter_by(hidden=False).all()
            for test in bgp_tests:
                instance = TestInstance(
                    test_run_id=test_run.id,
                    device_id=test.devicehostname_id,
                    test_type="bgpaspath_test",
                    bgpaspath_test_id=test.id
                )
                test_instances.append(instance)
                
            txrxtransceiver_tests = txrxtransceiverTest.query.filter_by(hidden=False).all()
            for test in txrxtransceiver_tests:
                instance = TestInstance(
                    test_run_id=test_run.id,
                    device_id=test.devicehostname_id,
                    test_type="txrxtransceiver_test",
                    txrxtransceiver_test_id=test.id
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
            new_credential.created_by_id=current_user.id
            db.session.add(new_credential)
            db.session.commit()
            return jsonify({'message': 'User added'})
        credentials = DeviceCredential.query.filter_by(hidden=False).all()
        return render_template('credentials.html', credentials=credentials, form=form)

    # Delete credential
    @app.route('/delete_credential/<int:credential_id>', methods=['POST'])
    @login_required
    def delete_credential(credential_id):
        credential = DeviceCredential.query.get_or_404(credential_id)
        credential.hidden = True
        db.session.commit()
        return jsonify({'message': 'Credential deleted successfully'})

    @app.route('/devices')
    @login_required
    def device_list():
        devices = Device.query.filter_by(hidden=False).all()
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
                        numerictraceroute=form.numerictraceroute.data,
                        created_by_id=current_user.id
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
        device.hidden = True
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
         # Query all non-hidden bgpaspath tests
        bgpaspathtests = bgpaspathTest.query.filter_by(hidden=False).all()
        
        # Create a list of dictionaries with test data and owner flag
        tests_with_owner = []
        for test in bgpaspathtests:
            test_data = {
                'id': test.id,
                'devicehostname': test.devicehostname,
                'testipv4prefix': test.testipv4prefix,
                'checkasinpath': test.checkasinpath,
                'checkaswantresult': test.checkaswantresult,
                'description': test.description,
                'created_by': test.created_by,
                'owner': test.created_by_id == current_user.id,  # True if item creator = current user, otherwise False
                'owner_name': test.created_by.username if test.created_by else 'Unknown'
            }
            tests_with_owner.append(test_data)
        
        # Pass the modified dataset to the template
        return render_template('showtests_bgpaspath.html', bgpaspathtests=tests_with_owner)

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
                        description=form.test_description.data,
                        created_by_id=current_user.id
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
        if test.created_by_id == current_user.id:
            test.hidden = True
            db.session.commit()
            return jsonify({'message': 'BGP AS-path Test removed successfully'})
        else:
            return jsonify({'message': 'You did not create this test'})

    # Display all Traceroute Tests
    @app.route('/tests/traceroute', methods=['GET'])
    @login_required
    def showtests_traceroute():
        traceroutetests = tracerouteTest.query.filter_by(hidden=False).all()
        tests_with_owner = []
        for test in traceroutetests:
            test_data = {
                'id': test.id,
                'devicehostname': test.devicehostname,
                'destinationip': test.destinationip,
                'description': test.description,
                'created_by': test.created_by,
                'owner': test.created_by_id == current_user.id,  # True if item creator = current user, otherwise False
                'owner_name': test.created_by.username if test.created_by else 'Unknown'
            }
            tests_with_owner.append(test_data)
        return render_template('showtests_traceroute.html', traceroutetests=tests_with_owner)

    # Add Traceroute test
    @app.route('/tests/addtest_traceroute', methods=['GET', 'POST'])
    @login_required
    def addtest_traceroute():
        form = tracerouteTestForm()
        if request.method == 'POST':
            if form.validate_on_submit():  # Form validation
                try:
                    # Create a new traceroute test using the form data
                    new_test = tracerouteTest(
                        devicehostname_id=form.test_device_hostname.data,
                        destinationip=form.test_destinationip.data,
                        description=form.test_description.data,
                        created_by_id=current_user.id
                    )
                    db.session.add(new_test)
                    db.session.commit()
                    ''' return jsonify({'redirect': url_for('showtests_traceroute')})  # Redirect back to traceroute tests list '''
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
        if test.created_by_id == current_user.id:
            test.hidden = True
            db.session.commit()
            return jsonify({'message': 'Traceroute Test removed successfully'})
        else:
            return jsonify({'message': 'You did not create this test'})

    # Display all TxRx SFP Transceiver Tests
    @app.route('/tests/txrxtransceiver', methods=['GET'])
    @login_required
    def showtests_txrxtransceiver():
        txrxtransceivertests = txrxtransceiverTest.query.filter_by(hidden=False).all()
        tests_with_owner = []
        for test in txrxtransceivertests:
            test_data = {
                'id': test.id,
                'devicehostname': test.devicehostname,
                'deviceinterface': test.deviceinterface,
                'description': test.description,
                'created_by': test.created_by,
                'owner': test.created_by_id == current_user.id,  # True if item creator = current user, otherwise False
                'owner_name': test.created_by.username if test.created_by else 'Unknown'
            }
            tests_with_owner.append(test_data)
        return render_template('showtests_txrxtransceiver.html', txrxtransceivertests=tests_with_owner)

    # Add TxRx SFP Transceiver test
    @app.route('/tests/addtest_txrxtransceiver', methods=['GET', 'POST'])
    @login_required
    def addtest_txrxtransceiver():
        form = txrxtransceiverTestForm()
        if request.method == 'POST':
            if form.validate_on_submit():  # Form validation
                try:
                    # Create a new txrxtransceiver test using the form data
                    new_test = txrxtransceiverTest(
                        devicehostname_id=form.test_device_hostname.data,
                        deviceinterface=form.test_deviceinterface.data,
                        description=form.test_description.data,
                        created_by_id=current_user.id
                    )
                    db.session.add(new_test)
                    db.session.commit()
                    return redirect(url_for('showtests_txrxtransceiver'))
                except Exception as e:
                    db.session.rollback()  # In case of any error, rollback the session
                    print("Error adding device:", str(e))
                    return jsonify({'message': 'Database error: ' + str(e)}), 500
            # If form validation fails, return specific errors
            error_messages = {field: error for field,
                              error in form.errors.items()}
            return jsonify({'message': 'Form validation failed', 'errors': error_messages}), 400
        # If GET request, render form
        return render_template("addtest_txrxtransceiver.html", form=form)

    # Delete Traceroute Test
    @app.route('/tests/delete_txrxtransceivertest/<int:test_id>', methods=['POST'])
    @login_required
    def delete_txrxtransceivertest(test_id):
        test = txrxtransceiverTest.query.get_or_404(test_id)
        if test.created_by_id == current_user.id:
            test.hidden = True
            db.session.commit()
            return jsonify({'message': 'TxRx SFP Transceiver Test removed successfully'})
        else:
            return jsonify({'message': 'You did not create this test'})


    # Display all ACI itraceroute Tests
    @app.route('/tests/itraceroute', methods=['GET'])
    @login_required
    def showtests_itraceroute():
        itraceroutetests = itracerouteTest.query.filter_by(hidden=False).all()
        tests_with_owner = []
        for test in itraceroutetests:
            test_data = {
                'id': test.id,
                'devicehostname': test.devicehostname,
                'srcip': test.srcip,
                'dstip': test.dstip,
                'vrf': test.vrf,
                'encapvlan': test.encapvlan,
                'description': test.description,
                'created_by': test.created_by,
                'owner': test.created_by_id == current_user.id,  # True if item creator = current user, otherwise False
                'owner_name': test.created_by.username if test.created_by else 'Unknown'
            }
            tests_with_owner.append(test_data)
        return render_template('showtests_itraceroute.html', itraceroutetests=tests_with_owner)

    # Add ACI itraceroute test
    @app.route('/tests/addtest_itraceroute', methods=['GET', 'POST'])
    @login_required
    def addtest_itraceroute():
        form = itracerouteTestForm()
        if request.method == 'POST':
            if form.validate_on_submit():  # Form validation
                try:
                    # Create a new itraceroute test using the form data
                    new_test = itracerouteTest(
                        devicehostname_id=form.test_device_hostname.data,
                        srcip=form.test_srcip.data,
                        dstip=form.test_dstip.data,
                        vrf=form.test_vrf.data,
                        encapvlan=form.test_encapvlan.data,
                        description=form.test_description.data,
                        created_by_id = current_user.id
                    )
                    db.session.add(new_test)
                    db.session.commit()
                    return redirect(url_for('showtests_itraceroute'))
                except Exception as e:
                    db.session.rollback()  # In case of any error, rollback the session
                    print("Error adding device:", str(e))
                    return jsonify({'message': 'Database error: ' + str(e)}), 500
            # If form validation fails, return specific errors
            error_messages = {field: error for field,
                              error in form.errors.items()}
            return jsonify({'message': 'Form validation failed', 'errors': error_messages}), 400
        # If GET request, render form
        return render_template("addtest_itraceroute.html", form=form)

    # Delete ACI itraceroute Test
    @app.route('/tests/delete_itraceroutetest/<int:test_id>', methods=['POST'])
    @login_required
    def delete_itraceroutetest(test_id):
        test = itracerouteTest.query.get_or_404(test_id)
        if test.created_by_id == current_user.id:
            test.hidden = True
            db.session.commit()
            return jsonify({'message': 'ACI itraceroute test removed successfully'})
        else:
            return jsonify({'message': 'You did not create this test'})

    @app.route('/test_results', defaults={'user_id': None})
    @app.route('/test_results/<int:user_id>')
    @login_required
    def list_test_results(user_id):
        """
        Display a table of all test runs initiated by a given user.
        If no user_id is provided, show test runs for all users.
        Hidden test results are omitted, sorted by start_time (most recent first).
        Includes total number of TestInstance records per TestRun (excluding skipped tests).
        """
        # Base query for TestRun
        query = db.session.query(TestRun).filter(TestRun.hidden == False)
        if user_id is not None:
            query = query.filter(TestRun.created_by_id == user_id)
        else:
            # Exclude results by user_id 2 (user2 if you have followed the install guide) as this user is only used for testing new features.
            # (user_id 1 is the admin)
            query = query.filter(TestRun.created_by_id != 2)
        query = query.order_by(TestRun.start_time.desc())
        test_runs = query.all()

        # Query to count total TestInstance records per TestRun (excluding skipped)
        # Subquery for each test type, filtering for device_active_at_run == True
        bgp_counts = (
            db.session.query(
                TestRun.id.label('test_run_id'),
                func.count(TestInstance.id).label('test_count')
            )
            .join(TestInstance, TestRun.id == TestInstance.test_run_id)
            .join(bgpaspathTestResult, TestInstance.id == bgpaspathTestResult.test_instance_id)
            .filter(
                TestRun.hidden == False,
                TestInstance.test_type == "bgpaspath_test",
                TestInstance.device_active_at_run == True
            )
            .group_by(TestRun.id)
        )

        traceroute_counts = (
            db.session.query(
                TestRun.id.label('test_run_id'),
                func.count(TestInstance.id).label('test_count')
            )
            .join(TestInstance, TestRun.id == TestInstance.test_run_id)
            .join(tracerouteTestResult, TestInstance.id == tracerouteTestResult.test_instance_id)
            .filter(
                TestRun.hidden == False,
                TestInstance.test_type == "traceroute_test",
                TestInstance.device_active_at_run == True
            )
            .group_by(TestRun.id)
        )

        txrxtransceiver_counts = (
            db.session.query(
                TestRun.id.label('test_run_id'),
                func.count(TestInstance.id).label('test_count')
            )
            .join(TestInstance, TestRun.id == TestInstance.test_run_id)
            .join(txrxtransceiverTestResult, TestInstance.id == txrxtransceiverTestResult.test_instance_id)
            .filter(
                TestRun.hidden == False,
                TestInstance.test_type == "txrxtransceiver_test",
                TestInstance.device_active_at_run == True
            )
            .group_by(TestRun.id)
        )

        itraceroute_counts = (
            db.session.query(
                TestRun.id.label('test_run_id'),
                func.count(TestInstance.id).label('test_count')
            )
            .join(TestInstance, TestRun.id == TestInstance.test_run_id)
            .join(itracerouteTestResult, TestInstance.id == itracerouteTestResult.test_instance_id)
            .filter(
                TestRun.hidden == False,
                TestInstance.test_type == "itraceroute_test",
                TestInstance.device_active_at_run == True
            )
            .group_by(TestRun.id)
        )

        # Combine counts using UNION ALL and wrap in a subquery
        total_counts_subquery = (
            bgp_counts.union_all(
                traceroute_counts,
                txrxtransceiver_counts,
                itraceroute_counts
            )
            .subquery()
        )

        # Aggregate total counts per test_run_id
        total_counts = (
            db.session.query(
                total_counts_subquery.c.test_run_id,
                func.sum(total_counts_subquery.c.test_count).label('total_tests')
            )
            .group_by(total_counts_subquery.c.test_run_id)
            .all()
        )

        # Convert to dictionary
        total_counts_dict = {row.test_run_id: row.total_tests for row in total_counts}

        # Attach total_tests to each TestRun object
        # Format start_time and end_time for each test run
        for test_run in test_runs:
            test_run.total_tests = total_counts_dict.get(test_run.id, 0)

            if test_run.start_time:
                day = test_run.start_time.day
                suffix = 'th' if 10 <= day % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
                test_run.formatted_start_time = test_run.start_time.strftime(f'{day}{suffix} %B %Y %H:%M')
            else:
                test_run.formatted_start_time = 'N/A'
            
            if test_run.end_time:
                day = test_run.end_time.day
                suffix = 'th' if 10 <= day % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
                test_run.formatted_end_time = test_run.end_time.strftime(f'{day}{suffix} %B %Y %H:%M')
            else:
                test_run.formatted_end_time = 'N/A'

        return render_template(
            'list_test_results.html',
            user_id=user_id,
            list_test_query_results=test_runs
        )
                            
    
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
            
            txrxtransceiver_base_query = (db.session.query(TestInstance, txrxtransceiverTestResult, Device, txrxtransceiverTest)
                                .join(txrxtransceiverTestResult, TestInstance.id == txrxtransceiverTestResult.test_instance_id)
                                .join(Device, TestInstance.device_id == Device.id)
                                .join(txrxtransceiverTest, TestInstance.txrxtransceiver_test_id ==txrxtransceiverTest.id )
                                .filter(TestInstance.test_run_id == run_id, TestInstance.test_type == "txrxtransceiver_test"))
            
            itraceroute_base_query = (db.session.query(TestInstance, itracerouteTestResult, Device, itracerouteTest)
                                .join(itracerouteTestResult, TestInstance.id == itracerouteTestResult.test_instance_id)
                                .join(Device, TestInstance.device_id == Device.id)
                                .join(itracerouteTest, TestInstance.itraceroute_test_id == itracerouteTest.id)
                                .filter(TestInstance.test_run_id == run_id, TestInstance.test_type == "itraceroute_test"))
            
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
            
            txrxtransceiver_totals = {
                'pass': sum(1 for _, r, _, _ in txrxtransceiver_base_query.filter(txrxtransceiverTestResult.passed == True).all()),
                'fail': sum(1 for _, r, _, _ in txrxtransceiver_base_query.filter(txrxtransceiverTestResult.passed == False).all()),
                'incomplete': sum(1 for ti, r, _, _ in txrxtransceiver_base_query.filter(txrxtransceiverTestResult.passed == None, TestInstance.device_active_at_run == True).all()),
                'skipped': sum(1 for ti, _, _, _ in txrxtransceiver_base_query.filter(TestInstance.device_active_at_run == False).all())
            }
            
            itraceroute_totals = {
                'pass': sum(1 for _, r, _, _ in itraceroute_base_query.filter(itracerouteTestResult.passed == True).all()),
                'fail': sum(1 for _, r, _, _ in itraceroute_base_query.filter(itracerouteTestResult.passed == False).all()),
                'incomplete': sum(1 for ti, r, _, _ in itraceroute_base_query.filter(itracerouteTestResult.passed == None, TestInstance.device_active_at_run == True).all()),
                'skipped': sum(1 for ti, _, _, _ in itraceroute_base_query.filter(TestInstance.device_active_at_run == False).all())
            }

            totals = {
                'pass': bgp_totals['pass'] + traceroute_totals['pass'] + txrxtransceiver_totals['pass'] + itraceroute_totals['pass'],
                'fail': bgp_totals['fail'] + traceroute_totals['fail'] + txrxtransceiver_totals['fail'] + itraceroute_totals['fail'],
                'incomplete': bgp_totals['incomplete'] + traceroute_totals['incomplete'] + txrxtransceiver_totals['incomplete'] + itraceroute_totals['incomplete'],
                'skipped': bgp_totals['skipped'] + traceroute_totals['skipped'] + txrxtransceiver_totals['skipped'] + itraceroute_totals['skipped']
            }

            # Filtered queries for display
            bgp_query = bgp_base_query
            traceroute_query = traceroute_base_query
            txrxtransceiver_query = txrxtransceiver_base_query
            itraceroute_query = itraceroute_base_query

            # Apply filters to display results
            if filter_type == 'pass':
                bgp_query = bgp_query.filter(bgpaspathTestResult.passed == True)
                traceroute_query = traceroute_query.filter(tracerouteTestResult.passed == True)
                txrxtransceiver_query = txrxtransceiver_query.filter(txrxtransceiverTestResult.passed == True)
                itraceroute_query = itraceroute_query.filter(itracerouteTestResult.passed == True)
            elif filter_type == 'fail':
                bgp_query = bgp_query.filter(bgpaspathTestResult.passed == False)
                traceroute_query = traceroute_query.filter(tracerouteTestResult.passed == False)
                txrxtransceiver_query = txrxtransceiver_query.filter(txrxtransceiverTestResult.passed == False)
                itraceroute_query = itraceroute_query.filter(itracerouteTestResult.passed == False)
            elif filter_type == 'incomplete':
                bgp_query = bgp_query.filter(bgpaspathTestResult.passed == None, TestInstance.device_active_at_run == True)
                traceroute_query = traceroute_query.filter(tracerouteTestResult.passed == None, TestInstance.device_active_at_run == True)
                txrxtransceiver_query = txrxtransceiver_query.filter(txrxtransceiverTestResult.passed == None, TestInstance.device_active_at_run == True)
                itraceroute_query = itraceroute_query.filter(itracerouteTestResult.passed == None, TestInstance.device_active_at_run == True)
            elif filter_type == 'skipped':
                bgp_query = bgp_query.filter(TestInstance.device_active_at_run == False)
                traceroute_query = traceroute_query.filter(TestInstance.device_active_at_run == False)
                txrxtransceiver_query = txrxtransceiver_query.filter(TestInstance.device_active_at_run == False)
                itraceroute_query = itraceroute_query.filter(TestInstance.device_active_at_run == False)

            bgp_results = bgp_query.all()
            traceroute_results = traceroute_query.all()
            txrxtransceiver_results = txrxtransceiver_query.all()
            itraceroute_results = itraceroute_query.all()

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
                            txrxtransceiver_results=txrxtransceiver_results,
                            itraceroute_results=itraceroute_results,
                            run_timestamp=run_timestamp,
                            run_endtimestamp=run_endtimestamp,
                            run_description=run_description,
                            run_log=run_log,
                            totals=totals)

    @app.route('/compare_results/picker', methods=['GET', 'POST'])
    @login_required
    def compare_test_runs_picker():
        """
        Render a form to select two TestRuns for comparison and handle submission.
        """
        form = CompareTestRunsForm()
        if form.validate_on_submit():
            test_run_1_id = form.test_run_1.data
            test_run_2_id = form.test_run_2.data
            if form.compare_type_x.data:
                # Redirect to "compare by pass/fail result" Type X comparison route
                return redirect(url_for('compare_test_runs_byresult', run_id_1=test_run_1_id, run_id_2=test_run_2_id))
            elif form.compare_type_y.data:
                # Redirect to "compare by raw cli output" Type Y comparison route
                return redirect(url_for('compare_test_runs_byrawoutput', run_id_1=test_run_1_id, run_id_2=test_run_2_id))
        return render_template('compare_test_runs_picker.html', form=form)


    @app.route('/compare_results/byresult', methods=['GET'])
    @login_required
    def compare_test_runs_byresult():
        """
        Compare two TestRuns by pass/fail result.
        """
        run_id_1 = request.args.get('run_id_1', type=int)
        run_id_2 = request.args.get('run_id_2', type=int)
        if not (run_id_1 and run_id_2):
            return render_template('error.html', message="Missing TestRun IDs"), 400

        test_run_1 = TestRun.query.get_or_404(run_id_1)
        test_run_2 = TestRun.query.get_or_404(run_id_2)
        
        # Format start times
        test_run_1_start_time_formatted = format_datetime_with_ordinal(test_run_1.start_time)
        test_run_2_start_time_formatted = format_datetime_with_ordinal(test_run_2.start_time)

        # Helper function to fetch comparison data for a test type
        def get_comparison_data(test_type, test_model, result_model):
            # Query TestInstances for both TestRuns, joining with test and result
            field_name = f"{test_type}_id"
                        
            try:
                instances_1 = db.session.query(
                    TestInstance,
                    test_model,
                    result_model,
                    Device
                ).join(
                    test_model,
                    getattr(TestInstance, field_name) == test_model.id
                ).outerjoin(
                    result_model,
                    TestInstance.id == result_model.test_instance_id
                ).join(
                    Device,
                    TestInstance.device_id == Device.id
                ).filter(
                    TestInstance.test_run_id == run_id_1,
                    TestInstance.test_type == test_type
                ).all()

                instances_2 = db.session.query(
                    TestInstance,
                    test_model,
                    result_model,
                    Device
                ).join(
                    test_model,
                    getattr(TestInstance, field_name) == test_model.id
                ).outerjoin(
                    result_model,
                    TestInstance.id == result_model.test_instance_id
                ).join(
                    Device,
                    TestInstance.device_id == Device.id
                ).filter(
                    TestInstance.test_run_id == run_id_2,
                    TestInstance.test_type == test_type
                ).all()

                test_ids = set([i[1].id for i in instances_1] + [i[1].id for i in instances_2])

                results = []
                for test_id in test_ids:
                    inst_1 = next((i for i in instances_1 if i[1].id == test_id), None)
                    inst_2 = next((i for i in instances_2 if i[1].id == test_id), None)

                    # Derive states based on device_active_at_run and passed
                    state_1 = 'skipped' if inst_1 and not inst_1[0].device_active_at_run else \
                            'pass' if inst_1 and inst_1[2] and inst_1[2].passed is True else \
                            'fail' if inst_1 and inst_1[2] and inst_1[2].passed is False else \
                            'n/a' if inst_1 and inst_1[2] and inst_1[2].passed is None else 'missing'
                    state_2 = 'skipped' if inst_2 and not inst_2[0].device_active_at_run else \
                            'pass' if inst_2 and inst_2[2] and inst_2[2].passed is True else \
                            'fail' if inst_2 and inst_2[2] and inst_2[2].passed is False else \
                            'n/a' if inst_2 and inst_2[2] and inst_2[2].passed is None else 'missing'

                    comparison = {
                        'test_id': test_id,
                        'description': inst_1[1].description if inst_1 else inst_2[1].description,
                        'device_hostname': inst_1[3].hostname if inst_1 else inst_2[3].hostname,
                        'state_1': state_1,
                        'state_2': state_2,
                        'active_1': inst_1[0].device_active_at_run if inst_1 else False,
                        'active_2': inst_2[0].device_active_at_run if inst_2 else False,
                        'rawoutput_1': inst_1[2].rawoutput if inst_1 and inst_1[2] and state_1 != 'missing' else None,
                        'rawoutput_2': inst_2[2].rawoutput if inst_2 and inst_2[2] and state_2 != 'missing' else None,
                        'display_text_1': 'Skipped' if state_1 == 'skipped' else \
                                        f"Passed<br><pre>{inst_1[2].rawoutput}</pre>" if state_1 == 'pass' and inst_1 and inst_1[2] and inst_1[2].rawoutput else \
                                        f"Failed<br><pre>{inst_1[2].rawoutput}</pre>" if state_1 == 'fail' and inst_1 and inst_1[2] and inst_1[2].rawoutput else \
                                        f"Inconclusive<br><pre>{inst_1[2].rawoutput}</pre>" if state_1 == 'n/a' and inst_1 and inst_1[2] and inst_1[2].rawoutput else \
                                        'No Result' if state_1 == 'n/a' else 'Missing',
                        'display_text_2': 'Skipped' if state_2 == 'skipped' else \
                                        f"Passed<br><pre>{inst_2[2].rawoutput}</pre>" if state_2 == 'pass' and inst_2 and inst_2[2] and inst_2[2].rawoutput else \
                                        f"Failed<br><pre>{inst_2[2].rawoutput}</pre>" if state_2 == 'fail' and inst_2 and inst_2[2] and inst_2[2].rawoutput else \
                                        f"Inconclusive<br><pre>{inst_2[2].rawoutput}</pre>" if state_2 == 'n/a' and inst_2 and inst_2[2] and inst_2[2].rawoutput else \
                                        'No Result' if state_2 == 'n/a' else 'Missing'
                    }

                    # Status logic for hiding and display
                    if state_1 == state_2 and state_1 != 'missing':
                        comparison['status'] = 'Same'
                        comparison['display_status'] = state_1.capitalize() if state_1 != 'n/a' else 'N/A'
                        comparison['icon_status'] = {
                            'pass': '✅✅ (same)',
                            'fail': '❌❌ (same)',
                            'n/a': '⚠️⚠️ (same)',
                            'skipped': '⏸️⏸️ (same)'
                        }[state_1]
                    else:
                        comparison['status'] = 'Different'
                        state_1_str = state_1.capitalize() if state_1 != 'n/a' else 'N/A'
                        state_2_str = state_2.capitalize() if state_2 != 'n/a' else 'N/A'
                        comparison['display_status'] = f'{state_1_str} vs {state_2_str}'
                        icon_1 = {'pass': '✅', 'fail': '❌', 'n/a': '⚠️', 'skipped': '⏸️', 'missing': '❓'}[state_1]
                        icon_2 = {'pass': '✅', 'fail': '❌', 'n/a': '⚠️', 'skipped': '⏸️', 'missing': '❓'}[state_2]
                        comparison['icon_status'] = f'{icon_1}{icon_2}'

                    results.append(comparison)
                
                return results
            except AttributeError as e:
                return []

        bgpaspath_results = get_comparison_data('bgpaspath_test', bgpaspathTest, bgpaspathTestResult)
        traceroute_results = get_comparison_data('traceroute_test', tracerouteTest, tracerouteTestResult)
        txrxtransceiver_results = get_comparison_data('txrxtransceiver_test', txrxtransceiverTest, txrxtransceiverTestResult)
        itraceroute_results = get_comparison_data('itraceroute_test', itracerouteTest, itracerouteTestResult)
        
        return render_template(
            'compare_byresult.html',
            test_run_1=test_run_1,
            test_run_2=test_run_2,
            test_run_1_start_time_formatted=test_run_1_start_time_formatted,
            test_run_2_start_time_formatted=test_run_2_start_time_formatted,
            bgpaspath_results=bgpaspath_results,
            traceroute_results=traceroute_results,
            txrxtransceiver_results=txrxtransceiver_results,
            itraceroute_results=itraceroute_results
        )

    @app.route('/compare_results/byrawoutput', methods=['GET'])
    @login_required
    def compare_test_runs_byrawoutput():
        """
        Compare two TestRuns by raw CLI output.
        """
        run_id_1 = request.args.get('run_id_1', type=int)
        run_id_2 = request.args.get('run_id_2', type=int)
        if not (run_id_1 and run_id_2):
            return render_template('error.html', message="Missing TestRun IDs"), 400

        test_run_1 = TestRun.query.get_or_404(run_id_1)
        test_run_2 = TestRun.query.get_or_404(run_id_2)
        
        # Format start times
        test_run_1_start_time_formatted = format_datetime_with_ordinal(test_run_1.start_time)
        test_run_2_start_time_formatted = format_datetime_with_ordinal(test_run_2.start_time)

        def get_comparison_data(test_type, test_model, result_model):
            field_name = f"{test_type}_id"
            instances_1 = db.session.query(
                TestInstance,
                test_model,
                result_model,
                Device
            ).join(
                test_model,
                getattr(TestInstance, field_name) == test_model.id
            ).outerjoin(
                result_model,
                TestInstance.id == result_model.test_instance_id
            ).join(
                Device,
                TestInstance.device_id == Device.id
            ).filter(
                TestInstance.test_run_id == run_id_1,
                TestInstance.test_type == test_type
            ).all()

            instances_2 = db.session.query(
                TestInstance,
                test_model,
                result_model,
                Device
            ).join(
                test_model,
                getattr(TestInstance, field_name) == test_model.id
            ).outerjoin(
                result_model,
                TestInstance.id == result_model.test_instance_id
            ).join(
                Device,
                TestInstance.device_id == Device.id
            ).filter(
                TestInstance.test_run_id == run_id_2,
                TestInstance.test_type == test_type
            ).all()

            results = []
            test_ids = set([i[1].id for i in instances_1] + [i[1].id for i in instances_2])
            
            for test_id in test_ids:
                inst_1 = next((i for i in instances_1 if i[1].id == test_id), None)
                inst_2 = next((i for i in instances_2 if i[1].id == test_id), None)

                comparison = {
                    'test_id': test_id,
                    'description': inst_1[1].description or 'No description' if inst_1 else inst_2[1].description or 'No description',
                    'device_hostname': inst_1[3].hostname if inst_1 else inst_2[3].hostname,
                    'passed_1': inst_1[2].passed if inst_1 and inst_1[2] else None,
                    'passed_2': inst_2[2].passed if inst_2 and inst_2[2] else None,
                    'active_1': inst_1[0].device_active_at_run if inst_1 else False,
                    'active_2': inst_2[0].device_active_at_run if inst_2 else False,
                    'rawoutput_1': inst_1[2].rawoutput if inst_1 and inst_1[2] else None,
                    'rawoutput_2': inst_2[2].rawoutput if inst_2 and inst_2[2] else None,
                    'status': 'N/A'
                }

                # Determine state for each test run
                state_1 = None
                state_2 = None
                if not comparison['active_1']:
                    state_1 = 'skipped'
                elif comparison['passed_1'] is None:
                    state_1 = 'no_result'
                elif comparison['passed_1']:
                    state_1 = 'pass'
                else:
                    state_1 = 'fail'

                if not comparison['active_2']:
                    state_2 = 'skipped'
                elif comparison['passed_2'] is None:
                    state_2 = 'no_result'
                elif comparison['passed_2']:
                    state_2 = 'pass'
                else:
                    state_2 = 'fail'

                # Map states to icons
                icon_map = {
                    'pass': '✅',
                    'fail': '❌',
                    'skipped': '⏸️',
                    'no_result': '⚠️'
                }

                # Set icon_status based on individual states
                icon_1 = icon_map[state_1] if state_1 else '⚠️'  # Default to warning if no state
                icon_2 = icon_map[state_2] if state_2 else '⚠️'  # Default to warning if no state
                comparison['icon_status'] = f"{icon_1}{icon_2}"

                # Determine status (Same/Different/N/A)
                if comparison['rawoutput_1'] is None or comparison['rawoutput_2'] is None:
                    comparison['status'] = 'N/A'
                else:
                    comparison['status'] = 'Same' if comparison['rawoutput_1'] == comparison['rawoutput_2'] else 'Different'
                    if comparison['status'] == 'Same':
                        comparison['icon_status'] += ' (exactly the same)'

                results.append(comparison)
            return results
        
        bgpaspath_results = get_comparison_data('bgpaspath_test', bgpaspathTest, bgpaspathTestResult)
        traceroute_results = get_comparison_data('traceroute_test', tracerouteTest, tracerouteTestResult)
        txrxtransceiver_results = get_comparison_data('txrxtransceiver_test', txrxtransceiverTest, txrxtransceiverTestResult)
        itraceroute_results = get_comparison_data('itraceroute_test', itracerouteTest, itracerouteTestResult)

        return render_template(
            'compare_byrawoutput.html',
            test_run_1=test_run_1,
            test_run_2=test_run_2,
            test_run_1_start_time_formatted=test_run_1_start_time_formatted,
            test_run_2_start_time_formatted=test_run_2_start_time_formatted,
            bgpaspath_results=bgpaspath_results,
            traceroute_results=traceroute_results,
            txrxtransceiver_results=txrxtransceiver_results,
            itraceroute_results=itraceroute_results
        )

    @app.route('/usersettings', methods=['GET','POST'])
    @login_required
    def usersettings():
        # Initialize forms
        password_form = ChangePasswordForm()
        theme_form = ThemeForm(current_theme=current_user.theme)

        # Set dropdown to current theme for GET requests or after failed POST
        if request.method == 'GET' or (request.method == 'POST' and not theme_form.validate()):
            if current_user.theme in [choice[0] for choice in theme_form.theme.choices]:
                theme_form.theme.data = current_user.theme
                logging.debug(f"Set dropdown theme to: {current_user.theme}")
            else:
                logging.debug(f"Invalid current theme: {current_user.theme}, falling back to default")
                theme_form.theme.data = 'default'

        if request.method == 'POST':
            logging.debug(f"POST request received with form data: {request.form}")
            form_name = request.form.get('form_name')
            logging.debug(f"Form name: {form_name}")

            # Dispatch to the appropriate form handler
            handlers = {
                'userpassword': handle_password_form,
                'theme': handle_theme_form,
            }
            handler = handlers.get(form_name)
            if handler:
                result = handler(password_form if form_name == 'userpassword' else theme_form)
                if result:
                    return result
            else:
                logging.debug(f"Unknown form_name: {form_name}")
                flash('Invalid form submission.', 'danger')

        return render_template('usersettings.html', password_form=password_form, theme_form=theme_form)

    @app.route('/faq')
    def faq():
        # FAQ data with embedded image placeholders and image list
        faq_data = [
            {
                'id': 'test-bgp-aspath',
                'question': 'What are the settings within a BGP AS-Path test?',
                'answer': 'This test looks at the BGP AS-Path for the current BEST PATH route for a given prefix. For example in this scenario there are 2 possible paths Branch Site 1 could take to internet. For various reasons you may have a preference for whether the Purple or Orange path is typically used. One reason might be geogrphic ie if one path has a significantly lower latency, or maybe higher bandwidth capacity. <br /><br />There are two ways the test can be configured. Both of these will result in a PASS result if the as-path goes via the Purple path: {image1} 1) To check if a given AS number *is* in the bestpath, eg does go via Data Centre A set "AS should exist in the as-path?" to Yes (ticked) and enter the AS number for A (ie 65101) {image2}{image4} 2) Alternatively to check if the best path *is not* via a certain AS set the option to No (unticked) and specifying the AS number to avoid (ie 65102 for B) {image3}{image5}',
                'images': [
                    'screenshots/bgp as-path 2 paths.png',
                    'screenshots/bgp as-path prefer path.png',
                    'screenshots/bgp as-path avoid path.png',
                    'screenshots/bgp via 65101.png',
                    'screenshots/bgp not via 65102.png'
                ]
            },
        ]
        
        '''
            {
                'id': 'test-frequency',
                'question': 'How often can I run a test?',
                'answer': 'Tests can be scheduled to run at intervals of 5 minutes, 15 minutes, or hourly, depending on your subscription plan.',
                'images': []  # No images
            },
            {
                'id': 'troubleshooting',
                'question': 'How do I troubleshoot a failed test?',
                'answer': 'Check the test logs for errors, as shown here: {image1}. Verify network connectivity and ensure the target is reachable.',
                'images': ['error_log_screenshot.png']  # Single image
            }
            '''
            
        return render_template('faq.html', faqs=faq_data)

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
            "txrxtransceiver_test": {"completed": 0, "running": 0, "skipped": 0, "total": 0},
            "itraceroute_test": {"completed": 0, "running": 0, "skipped": 0, "total": 0},
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

        DEVICE_TYPE_MAP = {
            "cisco_ios": "cisco_ios",
            "cisco_nxos": "cisco_nxos",
            "cisco_aci": "cisco_nxos",
        }

        conn_params = {
            "device_type": DEVICE_TYPE_MAP.get(device.devicetype, "cisco_ios"),  # Fallback to cisco_nxos
            "host": device.mgmtip,
            "username": cred.username,
            "password": cred.get_password(),
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
                            passed = is_traceroute_destination_reached(rawoutput,traceroute_test.destinationip)
                            result = tracerouteTestResult(test_instance_id=test.id, rawoutput=rawoutput, numberofhops=numberofhops, passed=passed)
                            db.session.add(result)
                            if passed is None:
                                log_msg = f"Device {device.hostname}: Traceroute test ID {test.id} incomplete - error parsing traceroute"
                            else:
                                log_msg = f"Device {device.hostname}: Traceroute test ID {test.id} completed - {'Passed' if passed else 'Failed'}"
                            with log_lock:
                                log_lines.append(log_msg)
                            socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})

                        elif test.test_type == "txrxtransceiver_test":
                            txrxtransceiver_test = test.txrxtransceiver_test
                            if device.devicetype == "cisco_ios":
                                rawoutput = conn.send_command(f"show int {txrxtransceiver_test.deviceinterface} transceiver")
                            elif device.devicetype == "cisco_nxos":
                                rawoutput = conn.send_command(f"show int {txrxtransceiver_test.deviceinterface} transceiver details")
                            if rawoutput:
                                # set default values
                                txrx = None
                                sfpinfo = None
                                if device.devicetype == "cisco_ios":
                                    sfppid = get_pid_from_ciscoios_output(rawoutput)
                                elif device.devicetype == "cisco_nxos":
                                    sfppid = get_pid_from_cisconxos_output(rawoutput)
                                if sfppid is not None:
                                    logger.info(f"sfppid: '{sfppid}' for run_id: {test_run_id}")
                                    sfpinfo = lookup_transceiver_info_for_pid(sfppid)
                                    if sfpinfo is not None:
                                        logger.info(f"sfpinfo: '{sfpinfo}' for run_id: {test_run_id}")
                                        if device.devicetype == "cisco_ios":
                                            txrx = parse_iosxe_transceiver_tx_rx(rawoutput)
                                            logger.info(f"txrx(ios): '{txrx}' for run_id: {test_run_id}")
                                        elif device.devicetype == "cisco_nxos":
                                            txrx = parse_nxos_transceiver_tx_rx(rawoutput)
                                            logger.info(f"txrx(nxos): '{txrx}' for run_id: {test_run_id}")
                                        if txrx is not None:
                                            if device.devicetype == "cisco_ios":
                                                passed = check_txrx_power_levels_ios(txrx)
                                            elif device.devicetype == "cisco_nxos":
                                                passed = check_txrx_power_levels_nxos(txrx)
                                            if passed is None:
                                                log_msg = f"Device {device.hostname}: TxRx test ID {test.id} incomplete - SFP found but unable to assess TxRx values"
                                        else:
                                            log_msg = f"Device {device.hostname}: TxRx test ID {test.id} incomplete - SFP found but unable to read TxRx values"
                                            passed = None
                                    else:
                                        log_msg = f"Device {device.hostname}: TxRx test ID {test.id} incomplete - SFP not a recognised model"
                                        passed = None
                                else:
                                    log_msg = f"Device {device.hostname}: TxRx test ID {test.id} incomplete - SFP not found"
                                    passed = None
                                result = txrxtransceiverTestResult(test_instance_id=test.id, rawoutput=rawoutput, passed=passed)
                                result.sfpinfo_dict = sfpinfo  # Serialize sfpinfo to JSON string
                                result.txrx_dict = txrx        # Serialize txrx to JSON string
                                db.session.add(result)
                                if passed is not None:
                                    log_msg = f"Device {device.hostname}: TxRx test ID {test.id} completed - {'Passed' if passed else 'Failed'}"
                                with log_lock:
                                    log_lines.append(log_msg)
                                socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})

                        elif test.test_type == "itraceroute_test":
                            itraceroute_test = test.itraceroute_test
                            if device.devicetype == "cisco_aci":
                                rawoutput = conn.send_command(
                                    command_string=f"itraceroute external src-ip {itraceroute_test.srcip} {itraceroute_test.dstip} vrf {itraceroute_test.vrf} encap vlan {itraceroute_test.encapvlan} icmp",
                                    read_timeout=90,
                                    use_textfsm=False,
                                    strip_prompt=True,
                                    strip_command=True
                                )
                                # example: itraceroute external src-ip 10.242.100.140 10.174.177.1 vrf PROD-INT:PROD-INT-VRF1 encap vlan 106 icmp
                                logger.info (f"itraceroute_test rawoutput: {rawoutput} for run_id: {test_run_id}")
                                passed = is_itraceroute_destination_reached(rawoutput)                                
                            else:
                                log_msg = f"Device {device.hostname}: itraceroute test not possible as not an ACI device"
                                passed = None
                            result = itracerouteTestResult(test_instance_id=test.id, rawoutput=rawoutput, passed=passed)
                            db.session.add(result)
                            log_msg = f"Device {device.hostname}: itraceroute test ID {test.id} completed - {'Passed' if passed else 'Failed'}"
                            with log_lock:
                                log_lines.append(log_msg)
                            socketio.emit('status_update', {'message': log_msg, 'run_id': test_run_id, 'level': 'child', 'device_id': device_id})

                        test.status = "completed"

                    except NetmikoTimeoutException as e:
                        handle_test_error(device, test, test_run_id, device_id, e, log_lock, log_lines, socketio, db)
                    except Exception as e:
                        handle_test_error(device, test, test_run_id, device_id, e, log_lock, log_lines, socketio, db)
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

# Mapping of test types to their result models and default values
TEST_TYPE_CONFIG = {
    "bgpaspath_test": {
        "model": bgpaspathTestResult,
        "default_fields": {
            "rawoutput": lambda e: f"Error: {str(e)}",
            "passed": None,
            "output": None
        }
    },
    "traceroute_test": {
        "model": tracerouteTestResult,
        "default_fields": {
            "rawoutput": lambda e: f"Error: {str(e)}",
            "numberofhops": None,
            "passed": None
        }
    },
    "txrxtransceiver_test": {
        "model": txrxtransceiverTestResult,
        "default_fields": {
            "rawoutput": lambda e: f"Error: {str(e)}",
            "sfpinfo": None,
            "txrx": None,
            "passed": None
        }
    },
    "itraceroute_test": {
        "model": itracerouteTestResult,
        "default_fields": {
            "rawoutput": lambda e: f"Error: {str(e)}",
            "passed": None
        }
    }
}

def handle_test_error(device, test, test_run_id, device_id, exception, log_lock, log_lines, socketio, db):
    """Handle test execution errors consistently across test types."""
    log_msg = f"Device {device.hostname}: {'Timeout' if isinstance(exception, NetmikoTimeoutException) else 'Error'} during test - {str(exception)}"
    
    with log_lock:
        log_lines.append(log_msg)
    
    socketio.emit('status_update', {
        'message': log_msg,
        'run_id': test_run_id,
        'level': 'child',
        'device_id': device_id
    })
    
    test.status = "failed"
    
    # Get test configuration
    test_config = TEST_TYPE_CONFIG.get(test.test_type)
    if not test_config:
        raise ValueError(f"Unknown test type: {test.test_type}")
    
    # Prepare result fields
    result_fields = {"test_instance_id": test.id}
    for field, value in test_config["default_fields"].items():
        result_fields[field] = value(exception) if callable(value) else value
    
    # Create and save result
    result = test_config["model"](**result_fields)
    db.session.add(result)
    db.session.commit()

def check_bgp_result(output, as_number, want_result):
    # Your logic to parse output and check if as_number appears as expected
    return as_number in output  # Simplified example

def count_hops(output):
    # Parse traceroute output to count hops (example)
    return len([line for line in output.splitlines() if line.strip().startswith(tuple(str(i) for i in range(1, 31)))])

def is_traceroute_destination_reached(output, targetip):
    """
    Parse check for standard traceroute output.
    Returns True if the destination IP is reached, False otherwise
    A failure to parse returns None
    """
    try:
        lines = output.strip().split('\n')
        
        # Process hop lines (lines starting with a number)
        for line in reversed(lines):
            line = line.strip()
            # Check if the line is a hop line (starts with a number)
            if line and line[0].isdigit() and targetip in line:
                return True
        return False
    except Exception:
        return None

def is_itraceroute_destination_reached(output):
    """
    Parses ACI leaf switch itraceroute output and returns True if the destination IP is reached,
    False otherwise, or None if parsing fails.

    Args:
        output (str): Multi-line string of itraceroute output.

    Returns:
        bool or None: True if the destination IP is the last hop, False if not, None if parsing fails.
    """
    try:
        # Extract the destination IP from the first line
        dest_match = re.search(r"traceroute to (\S+),", output)
        if not dest_match:
            logging.info("No destination IP found in traceroute output")
            return None
        dest_ip = dest_match.group(1)
        logging.info(f"Destination IP: {dest_ip}")

        # Find the external path section
        lines = output.splitlines()
        in_external = False
        hops = []

        for line in lines:
            # Detect start of external path table
            logging.info(f"Processing line: '{line}'")
            if "[ external ]" in line:
                in_external = True
                logging.info("Found external path section")
                continue
            # Look for hop lines in external path
            if in_external and line.strip().startswith("|"):
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 2 and parts[0].isdigit():
                    hop_ip = parts[1]
                    hops.append(hop_ip)
                    logging.info(f"Added hop: {hop_ip}")

        logging.info(f"Hops collected: {hops}")
        if not hops:
            logging.info("No hops found in external path")
            return False

        # Check if the last hop matches the destination IP
        result = hops[-1] == dest_ip
        logging.info(f"Last hop {hops[-1]} {'matches' if result else 'does not match'} destination {dest_ip}")
        return result

    except Exception as e:
        logging.error(f"Error parsing traceroute output: {str(e)}")
        return None

    except Exception:
        # Return False for any parsing errors
        return False

def get_pid_from_ciscoios_output(output):
    # 'show int ... transceiver'
    # relevant line of output looks like this
    # Product Identifier (PID)                  = SFP-10G-LR
    match = re.search(r"Product Identifier \(PID\)\s*=\s*(\S+)", output)
    return match.group(1) if match else None

def get_pid_from_cisconxos_output(output):
    # 'show int ... transceiver details'
    # relevant line of output looks like this
    # type is QSFP-100G-LR4
    match = re.search(r"type is (.+)", output)
    return match.group(1) if match else None
        
def lookup_transceiver_info_for_pid(pid):
    '''
    info = lookup_transceiver_info_for_pid("GLC-SX-MM")
    if info is not None:
        lanes = info['lanes']
        print (lanes)
        1
    else:
        print ("SFP info not known")
    '''
    
    transceiver_info = {
    # --- 1G SFPs (Single-lane) ---
    "GLC-LH-SM":       {"lanes": 1, "type": "SM", "distance": "10 km", "speed": "1G"},
    "GLC-LH-SMD":      {"lanes": 1, "type": "SM", "distance": "10 km", "speed": "1G"},
    "GLC-SX-MM":       {"lanes": 1, "type": "MM", "distance": "550 m", "speed": "1G"},
    "GLC-SX-MMD":      {"lanes": 1, "type": "MM", "distance": "550 m", "speed": "1G"},
    "GLC-ZX-SM":       {"lanes": 1, "type": "SM", "distance": "70–80 km", "speed": "1G"},
    "GLC-BX-U":        {"lanes": 1, "type": "SM", "distance": "10 km", "speed": "1G"},
    "GLC-BX-D":        {"lanes": 1, "type": "SM", "distance": "10 km", "speed": "1G"},

    # --- 10G SFP+ (Single-lane) ---
    "SFP-10G-SR":      {"lanes": 1, "type": "MM", "distance": "300 m", "speed": "10G"},
    "SFP-10G-LR":      {"lanes": 1, "type": "SM", "distance": "10 km", "speed": "10G"},
    "SFP-10G-ER":      {"lanes": 1, "type": "SM", "distance": "40 km", "speed": "10G"},
    "SFP-10G-ZR":      {"lanes": 1, "type": "SM", "distance": "80 km", "speed": "10G"},
    "SFP-10G-LRM":     {"lanes": 1, "type": "MM", "distance": "220 m", "speed": "10G"},
    "SFP-10G-BX10-U":  {"lanes": 1, "type": "SM", "distance": "10 km", "speed": "10G"},
    "SFP-10G-BX10-D":  {"lanes": 1, "type": "SM", "distance": "10 km", "speed": "10G"},
    "SFP-10G-DWDM":    {"lanes": 1, "type": "SM", "distance": "up to 80 km", "speed": "10G"},
    "SFP-10G-ZR-S":    {"lanes": 1, "type": "SM", "distance": "80 km", "speed": "10G"},
    "SFP-10G-SR-S":    {"lanes": 1, "type": "MM", "distance": "300 m", "speed": "10G"},
    "10Gbase-SR":      {"lanes": 1, "type": "MM", "distance": "300 m", "speed": "10G"},
    "Fabric Extender Transceiver": {"lanes": 1, "type": "MM", "distance": "100 m", "speed": "10G"},

    # --- 100G QSFP28 (Mostly 4-lane) ---
    "QSFP-100G-SR4":       {"lanes": 4, "type": "MM", "distance": "100 m", "speed": "100G"},
    "QSFP-100G-LR4":       {"lanes": 4, "type": "SM", "distance": "10 km", "speed": "100G"},
    "QSFP-100G-LR4-S":     {"lanes": 4, "type": "SM", "distance": "10 km", "speed": "100G"},
    "QSFP-100G-CWDM4":     {"lanes": 4, "type": "SM", "distance": "2 km", "speed": "100G"},
    "QSFP-100G-CWDM4-S":   {"lanes": 4, "type": "SM", "distance": "2 km", "speed": "100G"},
    "QSFP-100G-PSM4-S":    {"lanes": 4, "type": "SM", "distance": "500 m", "speed": "100G"},
    "QSFP-100G-ER4-Lite":  {"lanes": 4, "type": "SM", "distance": "25 km", "speed": "100G"},
    "QSFP-100G-ZR4-S":     {"lanes": 4, "type": "SM", "distance": "80 km", "speed": "100G"},
    "QSFP-100G-SRBD":      {"lanes": 2, "type": "MM", "distance": "100 m", "speed": "100G"},  # Bidirectional over 2 fibers
    "QSFP-100G-DR":        {"lanes": 1, "type": "SM", "distance": "500 m", "speed": "100G"},
    "QSFP-100G-DR-S":      {"lanes": 1, "type": "SM", "distance": "500 m", "speed": "100G"}
    }

    return transceiver_info.get(pid) # returns None is no match found

def parse_iosxe_transceiver_tx_rx(output):
    # parses Cisco IOS output of 'show interface ... transceiver' and returns the Tx Rx values
    # works for single-lane and multi-lane SFPs
    '''
    tx_rx = parse_transceiver_tx_rx(output)

    if tx_rx is not None:
        for lane, values in tx_rx.items():
            print(f"Lane {lane}: Tx = {values['tx_dBm']} dBm, Rx = {values['rx_dBm']} dBm")
    else:
        print("No Tx/Rx values found.")
        
    # example output: single-lane SFP
    { 0: {'tx_dBm': -2.1, 'rx_dBm': -3.2} }

    # example output: multi-lane SFP
    {
        0: {'tx_dBm': -1.6, 'rx_dBm': -2.0},
        1: {'tx_dBm': -1.5, 'rx_dBm': -2.1},
        2: {'tx_dBm': -1.4, 'rx_dBm': -2.2},
        3: {'tx_dBm': -1.5, 'rx_dBm': -2.0}
    }
    '''
    tx_rx_values = {}
    lines = output.splitlines()
    in_table = False
    is_multi_lane = False

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("Lane"):
            in_table = True
            is_multi_lane = True
            continue
        if in_table and stripped.startswith("---------"):
            continue
        if in_table and stripped:
            parts = line.split()
            if is_multi_lane:
                if len(parts) >= 6 and parts[0].isdigit():
                    lane = int(parts[0])
                    tx = float(parts[4])
                    rx = float(parts[5])
                    tx_rx_values[lane] = {"tx_dBm": tx, "rx_dBm": rx}
            else:
                # shouldn't get here on multi-lane
                pass
        elif in_table and not stripped:
            break

    # If no multi-lane match found, try single-lane style
    if not tx_rx_values:
        headers = None

        # Look for the data row directly
        for line in lines:
            if line.strip() and any(char.isdigit() for char in line):
                parts = ' '.join(line.split()).split()
                if len(parts) >= 6:  # Port, Temp, Voltage, Current, Tx, Rx
                    try:
                        tx = float(parts[4])  # Tx Power
                        rx = float(parts[5])  # Rx Power
                        tx_rx_values[0] = {"tx_dBm": tx, "rx_dBm": rx}
                        break
                    except (ValueError, IndexError):
                        continue

    return tx_rx_values or None

def check_txrx_power_levels_ios(data, threshold=-8):
    try:
        # Iterate through all lanes in the dataset
        for lane_data in data.values():
            # Get tx_dBm and rx_dBm
            tx = lane_data.get('tx_dBm')
            rx = lane_data.get('rx_dBm')
            
            # Check for None, "N/A", or non-numeric values
            for value in (tx, rx):
                if value is None or value == "N/A" or not isinstance(value, (int, float)):
                    return None
                
                # Compare against threshold (below threshold means > -8 mathematically)
                if value <= threshold:
                    return False
        
        # All values are above threshold
        return True
    
    except (AttributeError, TypeError, KeyError):
        # Handle malformed data (e.g., data not a dict, missing keys)
        return None

def check_txrx_power_levels_nxos(data):
    """
    Parses the txrx dict from parse_nxos_transceiver_tx_rx and returns True if all lanes
    are within tolerance, False if any are not, or None if there is an error determining
    the result.

    Args:
        data: Dict from parse_nxos_transceiver_tx_rx, e.g.,
              {0: {'tx_dBm': -2.63, 'rx_dBm': -3.62, 'within_tolerance': 'yes'}, ...}

    Returns:
        bool: True if all lanes have within_tolerance='yes', False if any are 'no'.
        None: If data is None, empty, or has invalid format.
    """
    # Check for invalid input
    if data is None or not isinstance(data, dict) or not data:
        logger.info(f"check_txrx_power_levels_nxos: problem with data '{data}' returning None")
        return None

    try:
        # Check each lane's within_tolerance
        for lane_data in data.values():
            if 'within_tolerance' not in lane_data:
                logger.info(f"check_txrx_power_levels_nxos: within_tolerence value not found in data '{data}' returning None")
                return None
            if lane_data['within_tolerance'] != 'yes':
                logger.info(f"check_txrx_power_levels_nxos: within_tolerence value not 'yes' in '{data}' returning False")
                return False
        # All lanes are 'yes'
        logger.info(f"check_txrx_power_levels_nxos: within_tolerence values all Yes in data '{data}' returning True")
        return True
    except (KeyError, TypeError):
        logger.info(f"check_txrx_power_levels_nxos: problem with data (KeyError or TypeError) '{data}' returning None")
        # Handle unexpected dict structure
        return None

def parse_nxos_transceiver_tx_rx(output):
    """
    Parses Cisco NX-OS 'show interface ... transceiver' output for Tx/Rx values.
    Works for single-lane and multi-lane SFPs. Includes within_tolerance check.

    Returns a dict like:
    # Single-lane SFP:
    { 0: {'tx_dBm': -2.63, 'rx_dBm': -3.62, 'within_tolerance': 'yes'} }

    # Multi-lane SFP:
    {
        0: {'tx_dBm': 2.70, 'rx_dBm': -2.44, 'within_tolerance': 'yes'},
        1: {'tx_dBm': 1.08, 'rx_dBm': -2.84, 'within_tolerance': 'yes'},
        ...
    }

    Returns None if no valid Tx/Rx values are found or if values are N/A.
    """
    logger.info("Starting to parse transceiver output")
    tx_rx_values = {}
    lines = output.splitlines()
    current_lane = None

    # Regex to match Tx/Rx Power lines
    power_pattern = re.compile(
        r"(Tx|Rx)\s+Power\s+(N/A|[-]?\d+\.\d+\s+dBm)\s+([-]?\d+\.\d+\s+dBm)\s+([-]?\d+\.\d+\s+dBm)\s+([-]?\d+\.\d+\s+dBm)\s+([-]?\d+\.\d+\s+dBm)"
    )

    # Temporary storage for Tx/Rx values per lane
    lane_data = {}

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Look for lane number
        lane_match = re.match(r"Lane Number:(\d+)", line)
        if lane_match:
            current_lane = int(lane_match.group(1)) - 1  # 0-based indexing
            logger.info(f"Detected lane: {current_lane + 1}")
            lane_data[current_lane] = {}
            continue

        # Match Tx/Rx Power lines
        power_match = power_pattern.search(line)
        if power_match:
            power_type = power_match.group(1)  # Tx or Rx
            current_value = power_match.group(2)  # Current measurement
            high_alarm = power_match.group(3)
            low_alarm = power_match.group(4)
            high_warning = power_match.group(5)
            low_warning = power_match.group(6)

            # Check for N/A
            if current_value == "N/A":
                logger.info(f"N/A found for {power_type} Power in lane {current_lane if current_lane is not None else 0}")
                return None

            # Set lane to 0 for single-lane SFPs if not already set
            if current_lane is None:
                current_lane = 0
                lane_data[current_lane] = {}
                logger.info("No lane number found, assuming single-lane SFP (lane 0)")

            try:
                current_value = float(current_value.split()[0])
                high_warning = float(high_warning.split()[0])
                low_warning = float(low_warning.split()[0])

                lane_data[current_lane][f"{power_type.lower()}_dBm"] = current_value
                lane_data[current_lane][f"{power_type.lower()}_high_warning"] = high_warning
                lane_data[current_lane][f"{power_type.lower()}_low_warning"] = low_warning
            except (ValueError, IndexError) as e:
                logger.info(f"Error parsing {power_type} Power line: {line}, error: {e}")
                continue

    # Process collected data
    for lane, data in lane_data.items():
        if "tx_dBm" in data and "rx_dBm" in data:
            tx_current = data["tx_dBm"]
            tx_high_warning = data["tx_high_warning"]
            tx_low_warning = data["tx_low_warning"]
            rx_current = data["rx_dBm"]
            rx_high_warning = data["rx_high_warning"]
            rx_low_warning = data["rx_low_warning"]

            # Check if within tolerance
            tx_within = tx_low_warning <= tx_current <= tx_high_warning
            rx_within = rx_low_warning <= rx_current <= rx_high_warning
            within_tolerance = "yes" if tx_within and rx_within else "no"

            tx_rx_values[lane] = {
                "tx_dBm": tx_current,
                "rx_dBm": rx_current,
                "within_tolerance": within_tolerance
            }
            logger.info(f"Parsed lane {lane}: tx_dBm={tx_current}, rx_dBm={rx_current}, within_tolerance={within_tolerance}")

    result = tx_rx_values if tx_rx_values else None
    logger.info(f"Parsing complete, result: {result}")
    return result

def handle_password_form(form):
    """Handle password change form submission."""
    logging.debug("Password form submitted")
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            if form.new_password.data == form.current_password.data:
                flash('New password cannot be the same as the current password.', 'danger')
            else:
                current_user.set_password(form.new_password.data)
                db.session.commit()
                flash('Password changed successfully!', 'success')
                return redirect(url_for('usersettings'))
        else:
            flash('Current password is incorrect.', 'danger')
    else:
        logging.debug(f"Password form errors: {form.errors}")
        flash('Error updating password.', 'danger')
    return None

def handle_theme_form(form):
    """Handle theme selection form submission."""
    raw_theme = request.form.get('theme')
    logging.debug(f"Theme form submitted with raw data: {raw_theme}, form data: {form.theme.data}")
    if form.validate_on_submit():
        logging.debug(f"Theme validated: {form.theme.data}")
        current_user.theme = form.theme.data
        logging.debug(f"Saving theme: {form.theme.data} for user: {current_user.username}")
        db.session.commit()
        flash('Theme updated successfully!', 'success')
        return redirect(url_for('usersettings'))
    else:
        logging.debug(f"Theme form errors: {form.errors}")
        flash(f"Error updating theme: {form.errors.get('theme', ['Unknown error'])[0]}", 'danger')
    return None

if __name__ == '__main__':
    # For local development only
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
