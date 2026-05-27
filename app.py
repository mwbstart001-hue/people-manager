from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
import functools
import os
import re

from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-this')
if SECRET_KEY == 'dev-secret-key-change-this' and os.environ.get('FLASK_ENV') != 'development':
    raise RuntimeError('SECRET_KEY must be set in production environment')

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///people.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

SESSION_LIFETIME_HOURS = int(os.environ.get('SESSION_LIFETIME_HOURS', '2'))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=SESSION_LIFETIME_HOURS)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'age': self.age,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


def is_valid_email(email):
    if not email:
        return True
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None


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


def is_locked_out(username):
    if username not in LOGIN_ATTEMPTS:
        return False
    attempts, lock_time = LOGIN_ATTEMPTS[username]
    if attempts >= MAX_LOGIN_ATTEMPTS:
        if datetime.utcnow() - lock_time < timedelta(minutes=LOCKOUT_MINUTES):
            remaining = int((LOCKOUT_MINUTES - (datetime.utcnow() - lock_time).total_seconds() / 60)) + 1
            return True, remaining
        else:
            LOGIN_ATTEMPTS.pop(username, None)
    return False, None


def record_login_attempt(username, success):
    if success:
        LOGIN_ATTEMPTS.pop(username, None)
    else:
        if username in LOGIN_ATTEMPTS:
            attempts, _ = LOGIN_ATTEMPTS[username]
            LOGIN_ATTEMPTS[username] = (attempts + 1, datetime.utcnow())
        else:
            LOGIN_ATTEMPTS[username] = (1, datetime.utcnow())


def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/register', methods=['POST'])
def register():
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
        app.logger.error(f'Registration error: {str(e)}')
        return jsonify({'error': '注册失败，请稍后重试'}), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': '请求格式错误，请使用 JSON 格式'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': '用户名和密码为必填项'}), 400
        
        locked, remaining = is_locked_out(username)
        if locked:
            return jsonify({
                'error': f'登录尝试次数过多，请等待 {remaining} 分钟后再试'
            }), 429
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            record_login_attempt(username, False)
            attempts, _ = LOGIN_ATTEMPTS.get(username, (0, None))
            remaining = MAX_LOGIN_ATTEMPTS - attempts
            return jsonify({
                'error': '用户名或密码错误',
                'remaining_attempts': remaining if remaining > 0 else 0
            }), 401
        
        record_login_attempt(username, True)
        
        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        session.permanent = True
        
        return jsonify({
            'message': '登录成功',
            'username': user.username,
            'session_expires_hours': SESSION_LIFETIME_HOURS
        }), 200
        
    except Exception as e:
        app.logger.error(f'Login error: {str(e)}')
        return jsonify({'error': '登录失败，请稍后重试'}), 500


@app.route('/logout', methods=['POST'])
def logout():
    try:
        session.clear()
        return jsonify({'message': '登出成功'}), 200
    except Exception as e:
        app.logger.error(f'Logout error: {str(e)}')
        return jsonify({'error': '登出失败，请稍后重试'}), 500


@app.route('/people', methods=['GET'])
@login_required
def get_people():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        if page < 1:
            page = 1
        if per_page < 1 or per_page > 100:
            per_page = 10
        
        pagination = Person.query.order_by(Person.created_at.desc()).paginate(
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
        app.logger.error(f'Get people error: {str(e)}')
        return jsonify({'error': '获取人员列表失败，请稍后重试'}), 500


@app.route('/people/<int:person_id>', methods=['GET'])
@login_required
def get_person(person_id):
    try:
        person = Person.query.get_or_404(person_id)
        return jsonify(person.to_dict()), 200
    except Exception as e:
        if '404' in str(e):
            return jsonify({'error': '人员不存在'}), 404
        app.logger.error(f'Get person error: {str(e)}')
        return jsonify({'error': '获取人员信息失败，请稍后重试'}), 500


@app.route('/people', methods=['POST'])
@login_required
def create_person():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': '请求格式错误，请使用 JSON 格式'}), 400
        
        name = data.get('name', '').strip()
        age = data.get('age')
        email = data.get('email', '').strip() if data.get('email') else None
        
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
        
        person = Person(
            name=name,
            age=age,
            email=email
        )
        
        db.session.add(person)
        db.session.commit()
        
        return jsonify({
            'message': '添加成功',
            'person': person.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Create person error: {str(e)}')
        return jsonify({'error': '添加人员失败，请稍后重试'}), 500


@app.route('/people/<int:person_id>', methods=['PUT'])
@login_required
def update_person(person_id):
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
        
        db.session.commit()
        
        return jsonify({
            'message': '修改成功',
            'person': person.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        if '404' in str(e):
            return jsonify({'error': '人员不存在'}), 404
        app.logger.error(f'Update person error: {str(e)}')
        return jsonify({'error': '修改人员信息失败，请稍后重试'}), 500


@app.route('/people/<int:person_id>', methods=['DELETE'])
@login_required
def delete_person(person_id):
    try:
        person = Person.query.get_or_404(person_id)
        
        db.session.delete(person)
        db.session.commit()
        
        return jsonify({'message': '删除成功'}), 200
        
    except Exception as e:
        db.session.rollback()
        if '404' in str(e):
            return jsonify({'error': '人员不存在'}), 404
        app.logger.error(f'Delete person error: {str(e)}')
        return jsonify({'error': '删除人员失败，请稍后重试'}), 500


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }), 200


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
