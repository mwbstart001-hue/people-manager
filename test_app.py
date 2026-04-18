import pytest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
import functools
import os
import re


def create_test_app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'test_secret_key_12345'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
    
    db = SQLAlchemy(app)
    
    LOGIN_ATTEMPTS = {}
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15
    
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        password_hash = db.Column(db.String(256), nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

        def set_password(self, password):
            self.password_hash = generate_password_hash(
                password,
                method='pbkdf2:sha256',
                salt_length=16
            )

        def check_password(self, password):
            return check_password_hash(self.password_hash, password)

    class Person(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(80), nullable=False)
        age = db.Column(db.Integer, nullable=True)
        email = db.Column(db.String(120), nullable=True)
        phone = db.Column(db.String(20), nullable=True)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

        def to_dict(self):
            return {
                'id': self.id,
                'name': self.name,
                'age': self.age,
                'email': self.email,
                'phone': self.phone,
                'created_at': self.created_at.isoformat() if self.created_at else None,
                'updated_at': self.updated_at.isoformat() if self.updated_at else None
            }

    def is_valid_email(email):
        if not email:
            return True
        pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        return re.match(pattern, email) is not None

    def is_valid_phone(phone):
        if not phone:
            return True
        if phone.startswith('+'):
            pattern = r'^\+\d{8,14}$'
        else:
            pattern = r'^\d{8,15}$'
        return re.match(pattern, phone) is not None

    def is_strong_password(password):
        if len(password) < 8:
            return False, '密码长度至少为8位'
        if len(password) > 128:
            return False, '密码长度不能超过128位'
        has_letter = re.search(r'[a-zA-Z]', password) is not None
        has_digit = re.search(r'\d', password) is not None
        if not (has_letter and has_digit):
            return False, '密码必须包含字母和数字'
        return True, None

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
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': '请求格式错误，请使用 JSON 格式'}), 400
            
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username or not password:
                return jsonify({'error': '用户名和密码为必填项'}), 400
            
            if len(username) < 2:
                return jsonify({'error': '用户名长度至少为2位'}), 400
            if len(username) > 80:
                return jsonify({'error': '用户名长度不能超过80位'}), 400
            
            is_strong, password_error = is_strong_password(password)
            if not is_strong:
                return jsonify({'error': password_error}), 400
            
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                return jsonify({'error': '用户名已存在'}), 400
            
            user = User(username=username)
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            return jsonify({
                'message': '注册成功',
                'user_id': user.id,
                'username': user.username
            }), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': '注册失败，请稍后重试'}), 500

    @app.route('/login', methods=['POST'])
    def login():
        from flask import request, jsonify, session
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': '请求格式错误，请使用 JSON 格式'}), 400
            
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username or not password:
                return jsonify({'error': '用户名和密码为必填项'}), 400
            
            user = User.query.filter_by(username=username).first()
            
            if not user or not user.check_password(password):
                return jsonify({
                    'error': '用户名或密码错误'
                }), 401
            
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            
            return jsonify({
                'message': '登录成功',
                'username': user.username
            }), 200
            
        except Exception as e:
            return jsonify({'error': '登录失败，请稍后重试'}), 500

    @app.route('/logout', methods=['POST'])
    def logout():
        from flask import session, jsonify
        try:
            session.clear()
            return jsonify({'message': '登出成功'}), 200
        except Exception as e:
            return jsonify({'error': '登出失败，请稍后重试'}), 500

    @app.route('/people', methods=['GET'])
    @login_required
    def get_people():
        from flask import request, jsonify
        try:
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 10, type=int)
            
            if page < 1:
                page = 1
            if per_page < 1 or per_page > 100:
                per_page = 10
            
            query = Person.query
            
            name = request.args.get('name', '').strip()
            if name:
                query = query.filter(Person.name.contains(name))
            
            email = request.args.get('email', '').strip()
            if email:
                query = query.filter(Person.email == email)
            
            age_min_str = request.args.get('age_min', '').strip()
            if age_min_str:
                try:
                    age_min = int(age_min_str)
                    if age_min < 0 or age_min > 150:
                        return jsonify({'error': '参数 age_min 必须在 0-150 之间'}), 400
                    query = query.filter(Person.age >= age_min)
                except (ValueError, TypeError):
                    return jsonify({'error': '参数 age_min 必须是有效的整数'}), 400
            
            age_max_str = request.args.get('age_max', '').strip()
            if age_max_str:
                try:
                    age_max = int(age_max_str)
                    if age_max < 0 or age_max > 150:
                        return jsonify({'error': '参数 age_max 必须在 0-150 之间'}), 400
                    query = query.filter(Person.age <= age_max)
                except (ValueError, TypeError):
                    return jsonify({'error': '参数 age_max 必须是有效的整数'}), 400
            
            pagination = query.order_by(Person.created_at.desc()).paginate(
                page=page,
                per_page=per_page,
                error_out=False
            )
            
            return jsonify({
                'data': [p.to_dict() for p in pagination.items],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': pagination.total,
                    'pages': pagination.pages
                }
            }), 200
            
        except Exception as e:
            return jsonify({'error': '获取人员列表失败，请稍后重试'}), 500

    @app.route('/people/<int:person_id>', methods=['GET'])
    @login_required
    def get_person(person_id):
        from flask import jsonify
        try:
            person = Person.query.get_or_404(person_id)
            return jsonify(person.to_dict()), 200
        except Exception as e:
            if '404' in str(e):
                return jsonify({'error': '人员不存在'}), 404
            return jsonify({'error': '获取人员信息失败，请稍后重试'}), 500

    @app.route('/people', methods=['POST'])
    @login_required
    def create_person():
        from flask import request, jsonify
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': '请求格式错误，请使用 JSON 格式'}), 400
            
            name = data.get('name', '').strip()
            age = data.get('age')
            email = data.get('email', '').strip() if data.get('email') else None
            phone = data.get('phone', '').strip() if data.get('phone') else None
            
            if not name:
                return jsonify({'error': '姓名为必填项'}), 400
            
            if len(name) > 80:
                return jsonify({'error': '姓名长度不能超过80位'}), 400
            
            if age is not None:
                try:
                    age = int(age)
                    if age < 0 or age > 150:
                        return jsonify({'error': '年龄必须在0-150之间'}), 400
                except (ValueError, TypeError):
                    return jsonify({'error': '年龄必须是有效的数字'}), 400
            
            if email:
                if len(email) > 120:
                    return jsonify({'error': '邮箱长度不能超过120位'}), 400
                if not is_valid_email(email):
                    return jsonify({'error': '邮箱格式不正确'}), 400
            
            if phone:
                if len(phone) > 20:
                    return jsonify({'error': '电话长度不能超过20位'}), 400
                if not is_valid_phone(phone):
                    return jsonify({'error': '电话格式不正确'}), 400
            
            person = Person(
                name=name,
                age=age,
                email=email,
                phone=phone
            )
            
            db.session.add(person)
            db.session.commit()
            
            return jsonify({
                'message': '添加成功',
                'person': person.to_dict()
            }), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': '添加人员失败，请稍后重试'}), 500

    @app.route('/people/<int:person_id>', methods=['PUT'])
    @login_required
    def update_person(person_id):
        from flask import request, jsonify
        try:
            person = Person.query.get_or_404(person_id)
            data = request.get_json()
            
            if not data:
                return jsonify({'error': '请求格式错误，请使用 JSON 格式'}), 400
            
            if 'name' in data:
                name = data['name'].strip() if data['name'] else ''
                if not name:
                    return jsonify({'error': '姓名不能为空'}), 400
                if len(name) > 80:
                    return jsonify({'error': '姓名长度不能超过80位'}), 400
                person.name = name
            
            if 'age' in data:
                age = data['age']
                if age is None:
                    person.age = None
                else:
                    try:
                        age = int(age)
                        if age < 0 or age > 150:
                            return jsonify({'error': '年龄必须在0-150之间'}), 400
                        person.age = age
                    except (ValueError, TypeError):
                        return jsonify({'error': '年龄必须是有效的数字'}), 400
            
            if 'email' in data:
                email = data['email'].strip() if data['email'] else None
                if email:
                    if len(email) > 120:
                        return jsonify({'error': '邮箱长度不能超过120位'}), 400
                    if not is_valid_email(email):
                        return jsonify({'error': '邮箱格式不正确'}), 400
                person.email = email
            
            if 'phone' in data:
                phone = data['phone'].strip() if data['phone'] else None
                if phone:
                    if len(phone) > 20:
                        return jsonify({'error': '电话长度不能超过20位'}), 400
                    if not is_valid_phone(phone):
                        return jsonify({'error': '电话格式不正确'}), 400
                person.phone = phone
            
            db.session.commit()
            
            return jsonify({
                'message': '修改成功',
                'person': person.to_dict()
            }), 200
            
        except Exception as e:
            db.session.rollback()
            if '404' in str(e):
                return jsonify({'error': '人员不存在'}), 404
            return jsonify({'error': '修改人员信息失败，请稍后重试'}), 500

    @app.route('/people/<int:person_id>', methods=['DELETE'])
    @login_required
    def delete_person(person_id):
        from flask import jsonify
        try:
            person = Person.query.get_or_404(person_id)
            
            db.session.delete(person)
            db.session.commit()
            
            return jsonify({'message': '删除成功'}), 200
            
        except Exception as e:
            db.session.rollback()
            if '404' in str(e):
                return jsonify({'error': '人员不存在'}), 404
            return jsonify({'error': '删除人员失败，请稍后重试'}), 500

    with app.app_context():
        db.create_all()
    
    return app


@pytest.fixture
def client():
    app = create_test_app()
    with app.test_client() as client:
        yield client


def get_valid_password():
    return 'Test123456'


def test_register_success(client):
    response = client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    assert response.status_code == 201
    data = response.get_json()
    assert 'user_id' in data
    assert 'username' in data


def test_register_password_too_short(client):
    response = client.post('/register', json={
        'username': 'testuser',
        'password': 'Abc123'
    })
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data


def test_register_password_no_letter(client):
    response = client.post('/register', json={
        'username': 'testuser',
        'password': '12345678'
    })
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data


def test_register_password_no_digit(client):
    response = client.post('/register', json={
        'username': 'testuser',
        'password': 'abcdefgh'
    })
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data


def test_register_username_too_short(client):
    response = client.post('/register', json={
        'username': 'a',
        'password': get_valid_password()
    })
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data


def test_register_duplicate_username(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    response = client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data


def test_register_missing_fields(client):
    response = client.post('/register', json={'username': 'testuser'})
    assert response.status_code == 400
    
    response = client.post('/register', json={'password': get_valid_password()})
    assert response.status_code == 400


def test_login_success(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    assert response.status_code == 200
    data = response.get_json()
    assert 'username' in data


def test_login_wrong_password(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'WrongPass123'
    })
    assert response.status_code == 401


def test_login_nonexistent_user(client):
    response = client.post('/login', json={
        'username': 'nonexistent',
        'password': get_valid_password()
    })
    assert response.status_code == 401


def test_logout(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
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


def test_create_person_invalid_age(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    response = client.post('/people', json={
        'name': '张三',
        'age': -1,
        'email': 'zhangsan@example.com'
    })
    assert response.status_code == 400
    
    response = client.post('/people', json={
        'name': '张三',
        'age': 200,
        'email': 'zhangsan@example.com'
    })
    assert response.status_code == 400
    
    response = client.post('/people', json={
        'name': '张三',
        'age': 'not_a_number',
        'email': 'zhangsan@example.com'
    })
    assert response.status_code == 400


def test_create_person_invalid_email(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    response = client.post('/people', json={
        'name': '张三',
        'age': 25,
        'email': 'invalid-email'
    })
    assert response.status_code == 400


def test_crud_operations(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
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
    assert len(data['data']) == 1
    
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
    assert len(data['data']) == 0


def test_pagination(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    for i in range(15):
        client.post('/people', json={
            'name': f'用户{i}',
            'age': 20 + i,
            'email': f'user{i}@example.com'
        })
    
    response = client.get('/people?page=1&per_page=10')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 10
    assert data['pagination']['total'] == 15
    assert data['pagination']['pages'] == 2
    
    response = client.get('/people?page=2&per_page=10')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 5


def test_full_workflow(client):
    response = client.post('/register', json={
        'username': 'admin',
        'password': get_valid_password()
    })
    assert response.status_code == 201
    
    response = client.post('/login', json={
        'username': 'admin',
        'password': get_valid_password()
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
    assert len(response.get_json()['data']) == 2
    
    response = client.put(f'/people/{person1_id}', json={
        'email': 'new_lisi@example.com'
    })
    assert response.status_code == 200
    
    response = client.delete(f'/people/{person2_id}')
    assert response.status_code == 200
    
    response = client.get('/people')
    assert response.status_code == 200
    assert len(response.get_json()['data']) == 1
    
    response = client.post('/logout')
    assert response.status_code == 200
    
    response = client.get('/people')
    assert response.status_code == 401


def test_create_person_valid_phone(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    response = client.post('/people', json={
        'name': '张三',
        'age': 25,
        'phone': '13812345678'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data['person']['phone'] == '13812345678'
    
    response = client.post('/people', json={
        'name': '李四',
        'age': 30,
        'phone': '+8613812345678'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data['person']['phone'] == '+8613812345678'
    
    response = client.post('/people', json={
        'name': '王五',
        'age': 28
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data['person']['phone'] is None


def test_create_person_invalid_phone(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    response = client.post('/people', json={
        'name': '张三',
        'age': 25,
        'phone': '1234567'
    })
    assert response.status_code == 400
    
    response = client.post('/people', json={
        'name': '李四',
        'age': 30,
        'phone': '1234567890123456'
    })
    assert response.status_code == 400
    
    response = client.post('/people', json={
        'name': '王五',
        'age': 28,
        'phone': '+1234567'
    })
    assert response.status_code == 400
    
    response = client.post('/people', json={
        'name': '赵六',
        'age': 32,
        'phone': 'abc12345678'
    })
    assert response.status_code == 400


def test_update_person_phone(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    response = client.post('/people', json={
        'name': '张三',
        'age': 25
    })
    assert response.status_code == 201
    person_id = response.get_json()['person']['id']
    
    response = client.put(f'/people/{person_id}', json={
        'phone': '13998765432'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['person']['phone'] == '13998765432'
    
    response = client.put(f'/people/{person_id}', json={
        'phone': None
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['person']['phone'] is None


def test_name_fuzzy_search(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    client.post('/people', json={'name': '张三丰', 'age': 25})
    client.post('/people', json={'name': '张无忌', 'age': 30})
    client.post('/people', json={'name': '李小龙', 'age': 28})
    client.post('/people', json={'name': '张三', 'age': 22})
    
    response = client.get('/people?name=三')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 2
    
    response = client.get('/people?name=张')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 3
    
    response = client.get('/people?name=李小')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 1
    
    response = client.get('/people?name=小龙')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 1
    
    response = client.get('/people?name=不存在')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 0


def test_email_exact_search(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    client.post('/people', json={'name': '张三', 'age': 25, 'email': 'zhangsan@example.com'})
    client.post('/people', json={'name': '李四', 'age': 30, 'email': 'lisi@example.com'})
    client.post('/people', json={'name': '王五', 'age': 28, 'email': 'wangwu@example.com'})
    
    response = client.get('/people?email=zhangsan@example.com')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 1
    assert data['data'][0]['name'] == '张三'
    
    response = client.get('/people?email=nonexistent@example.com')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 0
    
    response = client.get('/people?email=zhangsan')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 0


def test_age_range_search(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    client.post('/people', json={'name': '青年', 'age': 18})
    client.post('/people', json={'name': '成年', 'age': 25})
    client.post('/people', json={'name': '中年', 'age': 40})
    client.post('/people', json={'name': '老年', 'age': 60})
    client.post('/people', json={'name': '无年龄', 'age': None})
    
    response = client.get('/people?age_min=25')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 3
    
    response = client.get('/people?age_max=40')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 3
    
    response = client.get('/people?age_min=20&age_max=50')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 2
    
    response = client.get('/people?age_min=25&age_max=25')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 1
    assert data['data'][0]['name'] == '成年'


def test_combined_filters(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    client.post('/people', json={'name': '张小明', 'age': 25, 'email': 'zhangxm@example.com'})
    client.post('/people', json={'name': '张小红', 'age': 30, 'email': 'zhangxh@example.com'})
    client.post('/people', json={'name': '李小明', 'age': 25, 'email': 'lixm@example.com'})
    client.post('/people', json={'name': '王小红', 'age': 30, 'email': 'wangxh@example.com'})
    
    response = client.get('/people?name=小&age_min=25&age_max=25')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 2
    
    response = client.get('/people?name=张&age_min=28')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 1
    assert data['data'][0]['name'] == '张小红'
    
    response = client.get('/people?email=zhangxm@example.com&age_min=20')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 1
    assert data['data'][0]['name'] == '张小明'


def test_invalid_filter_params_return_400(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    client.post('/login', json={
        'username': 'testuser',
        'password': get_valid_password()
    })
    
    client.post('/people', json={'name': '张三', 'age': 25})
    client.post('/people', json={'name': '李四', 'age': 30})
    
    response = client.get('/people?age_min=abc')
    assert response.status_code == 400
    data = response.get_json()
    assert 'age_min' in data['error']
    
    response = client.get('/people?age_max=-5')
    assert response.status_code == 400
    data = response.get_json()
    assert 'age_max' in data['error']
    
    response = client.get('/people?age_min=200')
    assert response.status_code == 400
    data = response.get_json()
    assert 'age_min' in data['error']
    
    response = client.get('/people?age_min=20&age_max=abc')
    assert response.status_code == 400
    data = response.get_json()
    assert 'age_max' in data['error']
    
    response = client.get('/people?name=&age_min=25')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 2
    
    response = client.get('/people?invalid_param=123&name=张')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['data']) == 1


def is_valid_email_ut(email):
    if not email:
        return True
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None


def is_valid_phone_ut(phone):
    if not phone:
        return True
    if phone.startswith('+'):
        pattern = r'^\+\d{8,14}$'
    else:
        pattern = r'^\d{8,15}$'
    return re.match(pattern, phone) is not None


def is_strong_password_ut(password):
    if len(password) < 8:
        return False, '密码长度至少为8位'
    if len(password) > 128:
        return False, '密码长度不能超过128位'
    has_letter = re.search(r'[a-zA-Z]', password) is not None
    has_digit = re.search(r'\d', password) is not None
    if not (has_letter and has_digit):
        return False, '密码必须包含字母和数字'
    return True, None


class TestIsStrongPassword:
    def test_password_too_short(self):
        valid, msg = is_strong_password_ut('Ab12345')
        assert valid is False
        assert '8位' in msg

    def test_password_exactly_8_chars(self):
        valid, msg = is_strong_password_ut('Abc12345')
        assert valid is True
        assert msg is None

    def test_password_128_chars(self):
        long_pass = 'A' + 'a' * 63 + '1' * 63
        assert len(long_pass) == 127
        valid, msg = is_strong_password_ut(long_pass + '2')
        assert valid is True
        assert msg is None

    def test_password_too_long(self):
        long_pass = 'A' + 'a' * 63 + '1' * 64
        assert len(long_pass) == 128
        valid, msg = is_strong_password_ut(long_pass + '2')
        assert valid is False
        assert '128位' in msg

    def test_password_no_letter(self):
        valid, msg = is_strong_password_ut('12345678')
        assert valid is False
        assert '字母' in msg

    def test_password_no_digit(self):
        valid, msg = is_strong_password_ut('Abcdefgh')
        assert valid is False
        assert '数字' in msg

    def test_password_with_special_chars(self):
        valid, msg = is_strong_password_ut('Test@123')
        assert valid is True
        assert msg is None

    def test_password_mixed_case(self):
        valid, msg = is_strong_password_ut('tEsT1234')
        assert valid is True
        assert msg is None


class TestIsValidEmail:
    def test_empty_email(self):
        assert is_valid_email_ut('') is True
        assert is_valid_email_ut(None) is True

    def test_valid_email_simple(self):
        assert is_valid_email_ut('user@example.com') is True
        assert is_valid_email_ut('user.name@example.com') is True

    def test_valid_email_with_underscore(self):
        assert is_valid_email_ut('user_name@example.com') is True

    def test_valid_email_with_plus(self):
        assert is_valid_email_ut('user+tag@example.com') is True

    def test_valid_email_with_hyphen(self):
        assert is_valid_email_ut('user-name@example.com') is True

    def test_valid_email_subdomain(self):
        assert is_valid_email_ut('user@sub.example.com') is True

    def test_invalid_email_no_at(self):
        assert is_valid_email_ut('userexample.com') is False

    def test_invalid_email_no_domain(self):
        assert is_valid_email_ut('user@') is False

    def test_invalid_email_no_local(self):
        assert is_valid_email_ut('@example.com') is False

    def test_invalid_email_special_chars(self):
        assert is_valid_email_ut('user!name@example.com') is False

    def test_invalid_email_double_at(self):
        assert is_valid_email_ut('user@@example.com') is False


class TestIsValidPhone:
    def test_empty_phone(self):
        assert is_valid_phone_ut('') is True
        assert is_valid_phone_ut(None) is True

    def test_valid_phone_digits_8(self):
        assert is_valid_phone_ut('12345678') is True

    def test_valid_phone_digits_15(self):
        assert is_valid_phone_ut('123456789012345') is True

    def test_valid_phone_plus_9(self):
        assert is_valid_phone_ut('+12345678') is True

    def test_valid_phone_plus_15(self):
        assert is_valid_phone_ut('+12345678901234') is True

    def test_invalid_phone_too_short_7_digits(self):
        assert is_valid_phone_ut('1234567') is False

    def test_invalid_phone_too_long_16_digits(self):
        assert is_valid_phone_ut('1234567890123456') is False

    def test_invalid_phone_plus_too_short(self):
        assert is_valid_phone_ut('+1234567') is False

    def test_invalid_phone_plus_too_long(self):
        assert is_valid_phone_ut('+123456789012345') is False

    def test_invalid_phone_with_letters(self):
        assert is_valid_phone_ut('abc12345678') is False

    def test_invalid_phone_with_special_chars(self):
        assert is_valid_phone_ut('123-456-7890') is False

    def test_invalid_phone_with_spaces(self):
        assert is_valid_phone_ut(' 12345678 ') is False

    def test_invalid_phone_double_plus(self):
        assert is_valid_phone_ut('++12345678') is False

    def test_invalid_phone_plus_in_middle(self):
        assert is_valid_phone_ut('123+4567890') is False
