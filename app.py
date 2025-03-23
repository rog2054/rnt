from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tests.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Model
class TestConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    parameter = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')

# Create the database
with app.app_context():
    db.create_all()

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

# Run tests (simplified simulation)
@app.route('/run_tests')
def run_tests():
    tests = TestConfig.query.all()
    for test in tests:
        test.status = 'passed' if hash(test.test_name) % 2 == 0 else 'failed'
    db.session.commit()
    return jsonify({'message': 'Tests completed', 'results': [{'name': t.test_name, 'status': t.status} for t in tests]})

if __name__ == '__main__':
    app.run(debug=True)