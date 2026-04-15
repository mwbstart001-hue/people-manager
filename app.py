from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import functools

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///people.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret_key_123'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer)
    email = db.Column(db.String(120))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'age': self.age,
            'email': self.email
        }


def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': '用户名和密码为必填项'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': '用户名已存在'}), 400
    
    user = User(username=data['username'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': '注册成功', 'user_id': user.id}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': '用户名和密码为必填项'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'error': '用户名或密码错误'}), 401
    
    session['user_id'] = user.id
    session['username'] = user.username
    
    return jsonify({'message': '登录成功', 'username': user.username}), 200


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': '登出成功'}), 200


@app.route('/people', methods=['GET'])
@login_required
def get_people():
    people = Person.query.all()
    return jsonify([p.to_dict() for p in people]), 200


@app.route('/people/<int:person_id>', methods=['GET'])
@login_required
def get_person(person_id):
    person = Person.query.get_or_404(person_id)
    return jsonify(person.to_dict()), 200


@app.route('/people', methods=['POST'])
@login_required
def create_person():
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': '姓名为必填项'}), 400
    
    person = Person(
        name=data['name'],
        age=data.get('age'),
        email=data.get('email')
    )
    db.session.add(person)
    db.session.commit()
    
    return jsonify({'message': '添加成功', 'person': person.to_dict()}), 201


@app.route('/people/<int:person_id>', methods=['PUT'])
@login_required
def update_person(person_id):
    person = Person.query.get_or_404(person_id)
    data = request.get_json()
    
    if 'name' in data:
        person.name = data['name']
    if 'age' in data:
        person.age = data['age']
    if 'email' in data:
        person.email = data['email']
    
    db.session.commit()
    return jsonify({'message': '修改成功', 'person': person.to_dict()}), 200


@app.route('/people/<int:person_id>', methods=['DELETE'])
@login_required
def delete_person(person_id):
    person = Person.query.get_or_404(person_id)
    db.session.delete(person)
    db.session.commit()
    return jsonify({'message': '删除成功'}), 200


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
