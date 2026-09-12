import os
import uuid
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
from flask_cors import CORS

# Cargar variables de entorno locales (Render usará las suyas automáticamente)
load_dotenv()

app = Flask(__name__)
# Configuración CORS estricta para producción
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Configuración de la base de datos y seguridad
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'clave_respaldo_segura_veyra_2026') 
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- MODELOS DE DATOS ---

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String(100), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    lastName = db.Column(db.String(150), nullable=False, default='')
    documentId = db.Column(db.String(50), unique=True, nullable=False)
    phone1 = db.Column(db.String(50), nullable=False, default='')
    phone2 = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    creditLevel = db.Column(db.Integer, nullable=False, default=1)
    maxCreditAllowed = db.Column(db.Float, nullable=False, default=50.0)
    hasActiveLoan = db.Column(db.Boolean, default=False, nullable=False)
    
    loans = db.relationship('Loan', backref='user', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'lastName': self.lastName,
            'documentId': self.documentId,
            'phone1': self.phone1,
            'phone2': self.phone2,
            'email': self.email,
            'creditLevel': self.creditLevel,
            'maxCreditAllowed': self.maxCreditAllowed,
            'hasActiveLoan': self.hasActiveLoan
        }

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Loan(db.Model):
    __tablename__ = 'loans'
    
    id = db.Column(db.String(100), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(100), db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'amount': self.amount,
            'interest_rate': self.interest_rate,
            'due_date': self.due_date.isoformat()
        }

# --- ENDPOINTS PÚBLICOS (AUTENTICACIÓN) ---

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validación estricta y mejorada de campos obligatorios
    required_fields = ['name', 'email', 'password', 'documentId']
    
    if not data:
        return jsonify({'error': 'No se enviaron datos JSON'}), 400
        
    for field in required_fields:
        if field not in data or str(data.get(field)).strip() == "":
            return jsonify({'error': f'El campo obligatorio "{field}" falta o está vacío'}), 400
            
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'El correo ya está registrado'}), 409
        
    if User.query.filter_by(documentId=data['documentId']).first():
        return jsonify({'error': 'Esta cédula ya se encuentra registrada'}), 409

    new_user = User(
        name=data['name'],
        lastName=data.get('lastName', ''),
        documentId=data['documentId'],
        phone1=data.get('phone1', ''),
        phone2=data.get('phone2', ''),
        email=data['email']
    )
    new_user.set_password(data['password'])
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Usuario registrado exitosamente', 'user_id': new_user.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error interno al registrar el usuario'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Credenciales incompletas'}), 400

    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Correo o contraseña incorrectos'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({
        'token': access_token,
        'user': user.to_dict()
    }), 200

# --- ENDPOINTS PROTEGIDOS (REQUIEREN JWT) ---

@app.route('/api/users/me', methods=['GET'])
@jwt_required()
def get_my_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    return jsonify(user.to_dict()), 200

@app.route('/api/loans', methods=['POST'])
@jwt_required()
def create_loan():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or 'amount' not in data or 'due_date' not in data:
        return jsonify({'error': 'Faltan datos del préstamo'}), 400
        
    try:
        # Permite diferentes formatos de fecha manejando la 'Z' de UTC
        date_str = data['due_date'].replace('Z', '+00:00')
        due_date = datetime.fromisoformat(date_str)
    except (KeyError, ValueError):
        return jsonify({'error': 'Formato de fecha inválido. Use ISO 8601.'}), 400

    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'Usuario inválido'}), 404
        
    if user.hasActiveLoan:
        return jsonify({'error': 'El usuario ya tiene un préstamo activo'}), 403

    new_loan = Loan(
        user_id=current_user_id,
        amount=float(data['amount']),
        interest_rate=float(data.get('interest_rate', 0.15)),
        due_date=due_date
    )
    
    user.hasActiveLoan = True

    try:
        db.session.add(new_loan)
        db.session.commit()
        return jsonify(new_loan.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error interno al crear el préstamo'}), 500

@app.route('/api/loans/me', methods=['GET'])
@jwt_required()
def get_my_loans():
    current_user_id = get_jwt_identity()
    loans = Loan.query.filter_by(user_id=current_user_id).all()
    return jsonify([loan.to_dict() for loan in loans]), 200

# Inicialización de la base de datos
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)