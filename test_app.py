import pytest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import functools


def create_test_app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'test_secret_key'
    
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
            from flask import session, jsonify
            if 'user_id' not in session:
                return jsonify({'error': '请先登录'}), 401
            return f(*args, **kwargs)
        return decorated_function

    @app.route('/register', methods=['POST'])
    def register():
        from flask import request, jsonify
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
        from flask import request, jsonify, session
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
        from flask import session, jsonify
        session.clear()
        return jsonify({'message': '登出成功'}), 200

    @app.route('/people', methods=['GET'])
    @login_required
    def get_people():
        from flask import jsonify
        people = Person.query.all()
        return jsonify([p.to_dict() for p in people]), 200

    @app.route('/people/<int:person_id>', methods=['GET'])
    @login_required
    def get_person(person_id):
        from flask import jsonify
        person = Person.query.get_or_404(person_id)
        return jsonify(person.to_dict()), 200

    @app.route('/people', methods=['POST'])
    @login_required
    def create_person():
        from flask import request, jsonify
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
        from flask import request, jsonify
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
        from flask import jsonify
        person = Person.query.get_or_404(person_id)
        db.session.delete(person)
        db.session.commit()
        return jsonify({'message': '删除成功'}), 200

    with app.app_context():
        db.create_all()
    
    return app


@pytest.fixture
def client():
    app = create_test_app()
    with app.test_client() as client:
        yield client


def test_register_success(client):
    response = client.post('/register', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert 'user_id' in data


def test_register_duplicate_username(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    response = client.post('/register', json={
        'username': 'testuser',
        'password': 'anotherpass'
    })
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data


def test_register_missing_fields(client):
    response = client.post('/register', json={'username': 'testuser'})
    assert response.status_code == 400
    
    response = client.post('/register', json={'password': 'testpass'})
    assert response.status_code == 400


def test_login_success(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert 'username' in data


def test_login_wrong_password(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'wrongpass'
    })
    assert response.status_code == 401


def test_login_nonexistent_user(client):
    response = client.post('/login', json={
        'username': 'nonexistent',
        'password': 'testpass'
    })
    assert response.status_code == 401


def test_logout(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    response = client.post('/logout')
    assert response.status_code == 200


def test_permission_control_without_login(client):
    response = client.get('/people')
    assert response.status_code == 401
    
    response = client.post('/people', json={'name': 'John'})
    assert response.status_code == 401
    
    response = client.put('/people/1', json={'name': 'John'})
    assert response.status_code == 401
    
    response = client.delete('/people/1')
    assert response.status_code == 401


def test_crud_operations(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    response = client.post('/people', json={
        'name': '张三',
        'age': 25,
        'email': 'zhangsan@example.com'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data['person']['name'] == '张三'
    person_id = data['person']['id']
    
    response = client.get('/people')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == 1
    
    response = client.get(f'/people/{person_id}')
    assert response.status_code == 200
    data = response.get_json()
    assert data['name'] == '张三'
    
    response = client.put(f'/people/{person_id}', json={
        'name': '张三丰',
        'age': 30
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['person']['name'] == '张三丰'
    assert data['person']['age'] == 30
    
    response = client.delete(f'/people/{person_id}')
    assert response.status_code == 200
    
    response = client.get('/people')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == 0


def test_full_workflow(client):
    response = client.post('/register', json={
        'username': 'admin',
        'password': 'admin123'
    })
    assert response.status_code == 201
    
    response = client.post('/login', json={
        'username': 'admin',
        'password': 'admin123'
    })
    assert response.status_code == 200
    
    response = client.post('/people', json={
        'name': '李四',
        'age': 28,
        'email': 'lisi@example.com'
    })
    assert response.status_code == 201
    person1_id = response.get_json()['person']['id']
    
    response = client.post('/people', json={
        'name': '王五',
        'age': 32,
        'email': 'wangwu@example.com'
    })
    assert response.status_code == 201
    person2_id = response.get_json()['person']['id']
    
    response = client.get('/people')
    assert response.status_code == 200
    assert len(response.get_json()) == 2
    
    response = client.put(f'/people/{person1_id}', json={
        'email': 'new_lisi@example.com'
    })
    assert response.status_code == 200
    
    response = client.delete(f'/people/{person2_id}')
    assert response.status_code == 200
    
    response = client.get('/people')
    assert response.status_code == 200
    assert len(response.get_json()) == 1
    
    response = client.post('/logout')
    assert response.status_code == 200
    
    response = client.get('/people')
    assert response.status_code == 401
