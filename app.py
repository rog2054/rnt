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
from forms import DeviceForm, CredentialForm, bgpaspathTestForm, tracerouteTestForm, TestRunForm, CreateUserForm, LoginForm, txrxtransceiverTestForm, itracerouteTestForm
import netmiko
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import logging
import re
from datetime import datetime, timezone
from sqlalchemy import func


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
    login_manager.init_app(app)
    login_manager.login_view = 'login' # redirect unauth users to login route

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    with app.app_context():
        db.create_all()

    # Make version available to all templates
    @app.context_processor
    def inject_version():
        return dict(version=app.config['VERSION'])

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
                if current_user.id:
                    new_user.created_by_id = current_user.id
                else:
                    # default to admin as creator if not logged in, as that means the admin is creating the initial user account
                    new_user.created_by_id = 1
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
            bgp_tests = bgpaspathTest.query.filter_by(hidden=False).all()
            for test in bgp_tests:
                instance = TestInstance(
                    test_run_id=test_run.id,
                    device_id=test.devicehostname_id,
                    test_type="bgpaspath_test",
                    bgpaspath_test_id=test.id
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
                
            txrxtransceiver_tests = txrxtransceiverTest.query.filter_by(hidden=False).all()
            for test in txrxtransceiver_tests:
                instance = TestInstance(
                    test_run_id=test_run.id,
                    device_id=test.devicehostname_id,
                    test_type="txrxtransceiver_test",
                    txrxtransceiver_test_id=test.id
                )
                test_instances.append(instance)
                
            itraceroute_tests = itracerouteTest.query.filter_by(hidden=False).all()
            for test in itraceroute_tests:
                instance = TestInstance(
                    test_run_id=test_run.id,
                    device_id=test.devicehostname_id,
                    test_type="itraceroute_test",
                    itraceroute_test_id=test.id
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
        bgpaspathtests = bgpaspathTest.query.filter_by(hidden=False).all()
        return render_template('showtests_bgpaspath.html', bgpaspathtests=bgpaspathtests)

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
        test.hidden = True
        db.session.commit()
        return jsonify({'message': 'BGP AS-path Test removed successfully'})

    # Display all Traceroute Tests
    @app.route('/tests/traceroute', methods=['GET'])
    @login_required
    def showtests_traceroute():
        traceroutetests = tracerouteTest.query.filter_by(hidden=False).all()
        return render_template('showtests_traceroute.html', traceroutetests=traceroutetests)

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
        test.hidden = True
        db.session.commit()
        return jsonify({'message': 'Traceroute Test removed successfully'})

    # Display all TxRx SFP Transceiver Tests
    @app.route('/tests/txrxtransceiver', methods=['GET'])
    @login_required
    def showtests_txrxtransceiver():
        txrxtransceivertests = txrxtransceiverTest.query.filter_by(hidden=False).all()
        return render_template('showtests_txrxtransceiver.html', txrxtransceivertests=txrxtransceivertests)

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
        test.hidden=True
        db.session.commit()
        return jsonify({'message': 'TxRx SFP Transceiver Test removed successfully'})

    # Display all ACI itraceroute Tests
    @app.route('/tests/itraceroute', methods=['GET'])
    @login_required
    def showtests_itraceroute():
        itraceroutetests = itracerouteTest.query.filter_by(hidden=False).all()
        return render_template('showtests_itraceroute.html', itraceroutetests=itraceroutetests)

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
        test.hidden = True
        db.session.commit()
        return jsonify({'message': 'ACI itraceroute test removed successfully'})

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
                            passed = numberofhops > 3
                            result = tracerouteTestResult(test_instance_id=test.id, rawoutput=rawoutput, numberofhops=numberofhops, passed=passed)
                            db.session.add(result)
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
                                passed = is_traceroute_destination_reached(rawoutput)                                
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

def is_traceroute_destination_reached(output):
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


if __name__ == '__main__':
    # For local development only
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
