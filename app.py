from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
import threading
from time import sleep

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tests.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  # Needed for SocketIO
db = SQLAlchemy(app)
socketio = SocketIO(app)

# Database Model
class TestConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    parameter = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(100))  # None if dynamic
    is_dynamic = db.Column(db.Boolean, default=False)

# Create the database
with app.app_context():
    db.create_all()

# Delete a test
@app.route('/delete_test/<int:test_id>', methods=['POST'])
def delete_test(test_id):
    test = TestConfig.query.get_or_404(test_id)
    db.session.delete(test)
    db.session.commit()
    return jsonify({'message': 'Test deleted successfully'})

# Homepage with test config editor
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        test_name = request.form['test_name']
        category = request.form['category']
        parameter = request.form['parameter']
        
        new_test = TestConfig(test_name=test_name, category=category, parameter=parameter)
        db.session.add(new_test)
        db.session.commit()
        return jsonify({'message': 'Test added successfully'})
    
    categories = db.session.query(TestConfig.category).distinct().all()
    categories = [cat[0] for cat in categories]
    tests = TestConfig.query.all()
    return render_template('index.html', categories=categories, tests=tests)

# API to add new category dynamically (for validation)
@app.route('/add_category', methods=['POST'])
def add_category():
    new_category = request.json.get('category')
    if new_category and new_category not in [c.category for c in TestConfig.query.distinct(TestConfig.category)]:
        return jsonify({'message': 'Category available', 'category': new_category})
    return jsonify({'error': 'Category already exists'}), 400

# Device management route
@app.route('/devices', methods=['GET', 'POST'])
def manage_devices():
    if request.method == 'POST':
        device_name = request.form['device_name']
        username = request.form['username']
        password = request.form.get('password')
        is_dynamic = 'is_dynamic' in request.form
        new_device = Device(device_name=device_name, username=username, password=None if is_dynamic else password, is_dynamic=is_dynamic)
        db.session.add(new_device)
        db.session.commit()
        return jsonify({'message': 'Device added'})
    
    devices = Device.query.all()
    return render_template('devices.html', devices=devices)

# Simulate test execution (replace with your Netmiko logic)
def run_test_group(group_name, tests):
    total = len(tests)
    for i, test in enumerate(tests, 1):
        # Simulate work (replace with real Netmiko test)
        sleep(1)  # Simulate time taken
        test.status = 'passed' if hash(test.test_name) % 2 == 0 else 'failed'
        db.session.commit()
        # Emit progress update
        socketio.emit('progress', {
            'group': group_name,
            'completed': i,
            'total': total,
            'percentage': (i / total) * 100
        }, namespace='/test')

@app.route('/run_tests')
def run_tests_endpoint():
    tests = TestConfig.query.all()
    devices = Device.query.all()
    dynamic_devices = [d for d in devices if d.is_dynamic]
    
    if dynamic_devices:
        # Emit event to prompt for passwords
        socketio.emit('password_prompt', {
            'devices': [{'id': d.id, 'device_name': d.device_name, 'username': d.username} for d in dynamic_devices]
        }, namespace='/test')
        # Note: Test execution will proceed after passwords are submitted via SocketIO
    
    # Group tests (e.g., by category)
    grouped_tests = {}
    for test in tests:
        test.status = 'running'  # Mark as running before grouping
        grouped_tests.setdefault(test.category, []).append(test)
    db.session.commit()

    # If no dynamic devices, start tests immediately; otherwise, wait for passwords
    if not dynamic_devices:
        threads = []
        max_threads = 3
        for group_name, group_tests in list(grouped_tests.items())[:max_threads]:
            t = threading.Thread(target=run_test_group, args=(group_name, group_tests))
            threads.append(t)
            t.start()

        # Optionally wait for threads (uncomment if you want synchronous response)
        # for t in threads:
        #     t.join()

    return jsonify({'message': 'Tests started'})

@socketio.on('submit_passwords', namespace='/test')
def handle_passwords(data):
    passwords = data['passwords']  # {device_id: password}
    for device_id, password in passwords.items():
        device = Device.query.get(device_id)
        if device and device.is_dynamic:
            device.password = password  # Temporarily store for this run
    db.session.commit()

    # Now start the test execution after passwords are provided
    tests = TestConfig.query.all()
    grouped_tests = {}
    for test in tests:
        grouped_tests.setdefault(test.category, []).append(test)

    threads = []
    max_threads = 3
    for group_name, group_tests in list(grouped_tests.items())[:max_threads]:
        t = threading.Thread(target=run_test_group, args=(group_name, group_tests))
        threads.append(t)
        t.start()

    # Optionally wait for threads (uncomment if needed)
    # for t in threads:
    #     t.join()

# SocketIO background task (optional for cleanup)
@socketio.on('connect', namespace='/test')
def test_connect():
    print('Client connected for test updates')

if __name__ == '__main__':
    socketio.run(app, debug=True)