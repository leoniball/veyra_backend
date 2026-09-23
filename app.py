import os
import uuid
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
from flask_cors import CORS
import boto3
from botocore.exceptions import NoCredentialsError

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

# PARÁMETROS CRÍTICOS PARA NEON POSTGRESQL (Evita Error 500 por SSL cerrado)
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "pool_timeout": 30,
}

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- CLIENTE AMAZON S3 ---
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.getenv('S3_ACCESS_KEY'),
    aws_secret_access_key=os.getenv('S3_SECRET_KEY'),
    region_name=os.getenv('S3_REGION')
)
S3_BUCKET = os.getenv('S3_BUCKET_NAME')
S3_REGION = os.getenv('S3_REGION')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- FUNCIONES PARA ENVIAR CORREOS ---
def send_verification_email(to_email, code):
    sender_email = os.getenv('MAIL_USERNAME')
    sender_password = os.getenv('MAIL_PASSWORD')
    
    if not sender_email or not sender_password:
        print("ADVERTENCIA: Credenciales de correo no configuradas en entorno.")
        return False

    msg = MIMEMultipart()
    msg['From'] = f"Veyra Money <{sender_email}>"
    msg['To'] = to_email
    msg['Subject'] = "Tu código de verificación - Veyra Money"

    body = f"""
    Hola,
    
    Gracias por registrarte en Veyra Money. Tu código de verificación es:
    
    {code}
    
    Ingrésalo en la aplicación para activar tu cuenta.
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error enviando correo: {e}")
        return False

def send_reset_email(to_email, code):
    sender_email = os.getenv('MAIL_USERNAME')
    sender_password = os.getenv('MAIL_PASSWORD')
    
    if not sender_email or not sender_password:
        return False

    msg = MIMEMultipart()
    msg['From'] = f"Veyra Money <{sender_email}>"
    msg['To'] = to_email
    msg['Subject'] = "Recuperación de contraseña - Veyra Money"
    
    body = f"""
    Hola,

    Has solicitado restablecer tu contraseña en Veyra Money.
    
    Tu código de seguridad es: {code}
    
    Si no fuiste tú, ignora este mensaje.
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error enviando correo de recuperación: {e}")
        return False

def send_guarantor_email(to_email, code, user_name):
    sender_email = os.getenv('MAIL_USERNAME')
    sender_password = os.getenv('MAIL_PASSWORD')
    
    if not sender_email or not sender_password:
        return False

    msg = MIMEMultipart()
    msg['From'] = f"Veyra Money <{sender_email}>"
    msg['To'] = to_email
    msg['Subject'] = "Solicitud de Fiador - Veyra Money"
    
    body = f"""
    Hola,

    {user_name} te ha agregado como fiador solidario en Veyra Money.
    
    Para confirmar tu identidad y aceptar, proporciona el siguiente código al solicitante:
    
    {code}
    
    Si no conoces a esta persona, ignora este mensaje.
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error enviando correo al fiador: {e}")
        return False

def send_email_change_email(to_email, code):
    sender_email = os.getenv('MAIL_USERNAME')
    sender_password = os.getenv('MAIL_PASSWORD')
    
    if not sender_email or not sender_password:
        return False

    msg = MIMEMultipart()
    msg['From'] = f"Veyra Money <{sender_email}>"
    msg['To'] = to_email
    msg['Subject'] = "Confirmación de cambio de correo - Veyra Money"
    
    body = f"""
    Hola,

    Has solicitado asociar este correo a tu cuenta de Veyra Money.
    
    Tu código de seguridad para confirmar el cambio es: {code}
    
    Si no fuiste tú, por favor ignora este mensaje.
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error enviando correo de cambio de email: {e}")
        return False


# --- MODELOS DE DATOS ---

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String(100), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(150), nullable=False)
    lastName = db.Column(db.String(150), nullable=False, default='')
    documentId = db.Column(db.String(50), unique=True, nullable=False)
    phone1 = db.Column(db.String(50), nullable=False)
    phone2 = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    creditLevel = db.Column(db.Integer, nullable=False, default=1)
    maxCreditAllowed = db.Column(db.Float, nullable=False, default=50.0)
    hasActiveLoan = db.Column(db.Boolean, default=False, nullable=False)
    
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_code = db.Column(db.String(6), nullable=True)
    
    kyc_status = db.Column(db.String(20), default='pending')
    rif_url = db.Column(db.String(255), nullable=True)
    cedula_front_url = db.Column(db.String(255), nullable=True)
    selfie_url = db.Column(db.String(255), nullable=True)
    home_picture_url = db.Column(db.String(255), nullable=True)
    
    # --- NUEVOS CAMPOS: BLOQUEO DE KYC Y CAMBIO DE CORREO ---
    last_kyc_update = db.Column(db.DateTime, nullable=True)
    pending_email = db.Column(db.String(120), nullable=True)
    
    pm_cedula = db.Column(db.String(50), nullable=True)
    pm_phone = db.Column(db.String(50), nullable=True)
    pm_bank = db.Column(db.String(100), nullable=True)
    
    loans = db.relationship('Loan', backref='user', lazy=True)
    guarantors = db.relationship('Guarantor', backref='user', lazy=True, cascade="all, delete-orphan")

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
            'hasActiveLoan': self.hasActiveLoan,
            'is_verified': self.is_verified,
            'kyc_status': self.kyc_status,
            'cedula_front_url': self.cedula_front_url,
            'selfie_url': self.selfie_url,
            'rif_url': self.rif_url,
            'home_picture_url': self.home_picture_url,
            'last_kyc_update': self.last_kyc_update.isoformat() if self.last_kyc_update else None,
            'pending_email': self.pending_email,
            'pm_data': {
                'cedula': self.pm_cedula,
                'phone': self.pm_phone,
                'bank': self.pm_bank
            },
            'guarantors': [g.to_dict() for g in self.guarantors]
        }

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Guarantor(db.Model):
    __tablename__ = 'guarantors'
    
    id = db.Column(db.String(100), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(100), db.ForeignKey('users.id'), nullable=False)
    
    name = db.Column(db.String(150), nullable=False)
    cedula = db.Column(db.String(50), nullable=False)
    emergency_phone = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    
    is_email_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'cedula': self.cedula,
            'emergency_phone': self.emergency_phone,
            'email': self.email,
            'is_email_verified': self.is_email_verified
        }


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

@app.route('/', methods=['GET', 'HEAD'])
def home():
    return jsonify({"status": "Servidor Veyra activo y funcionando"}), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    required_fields = ['name', 'email', 'password', 'documentId', 'phone1']
    if not data:
        return jsonify({'error': 'No se enviaron datos JSON'}), 400
        
    for field in required_fields:
        if field not in data or str(data.get(field)).strip() == "":
            return jsonify({'error': f'El campo obligatorio "{field}" falta o está vacío'}), 400
            
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'El correo ya está registrado'}), 409
        
    if User.query.filter_by(documentId=data['documentId']).first():
        return jsonify({'error': 'Esta cédula ya se encuentra registrada'}), 409

    phone1 = data['phone1'].strip()
    if User.query.filter_by(phone1=phone1).first() or User.query.filter_by(phone2=phone1).first():
        return jsonify({'error': 'El teléfono principal ya está registrado en otra cuenta'}), 409
        
    phone2 = data.get('phone2', '').strip()
    if phone2 != "":
        if User.query.filter_by(phone1=phone2).first() or User.query.filter_by(phone2=phone2).first():
            return jsonify({'error': 'El teléfono secundario ya está registrado en otra cuenta'}), 409

    otp_code = str(random.randint(100000, 999999))

    new_user = User(
        name=data['name'],
        lastName=data.get('lastName', ''),
        documentId=data['documentId'],
        phone1=phone1,
        phone2=phone2,
        email=data['email'],
        is_verified=False,
        verification_code=otp_code
    )
    new_user.set_password(data['password'])
    
    try:
        db.session.add(new_user)
        db.session.commit()
        send_verification_email(new_user.email, otp_code)
        
        return jsonify({'message': 'Usuario registrado exitosamente.', 'user_id': new_user.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error interno al registrar el usuario'}), 500

@app.route('/api/auth/verify', methods=['POST'])
def verify_account():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('code'):
        return jsonify({'error': 'Faltan datos de verificación'}), 400
        
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
        
    if user.is_verified:
        return jsonify({'message': 'La cuenta ya estaba verificada'}), 200
        
    if user.verification_code != data['code']:
        return jsonify({'error': 'El código de verificación es incorrecto'}), 401
        
    user.is_verified = True
    user.verification_code = None 
    db.session.commit()
    
    return jsonify({'message': 'Cuenta verificada exitosamente'}), 200

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Credenciales incompletas'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Correo o contraseña incorrectos'}), 401

    if not user.is_verified:
        return jsonify({'error': 'Debes verificar tu correo electrónico antes de iniciar sesión', 'needs_verification': True}), 403

    access_token = create_access_token(identity=user.id)
    return jsonify({
        'token': access_token,
        'user': user.to_dict()
    }), 200

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data or not data.get('email'):
        return jsonify({'error': 'Falta el correo'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'error': 'No existe una cuenta con este correo'}), 404

    otp_code = str(random.randint(100000, 999999))
    user.verification_code = otp_code
    db.session.commit()

    send_reset_email(user.email, otp_code)
    return jsonify({'message': 'Código enviado'}), 200

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('code') or not data.get('new_password'):
        return jsonify({'error': 'Datos incompletos'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user or user.verification_code != data['code']:
        return jsonify({'error': 'Código inválido o expirado'}), 401

    user.set_password(data['new_password'])
    user.verification_code = None
    db.session.commit()

    return jsonify({'message': 'Contraseña actualizada'}), 200

# --- EDICIÓN DE PERFIL Y CAMBIO DE CORREO ---

@app.route('/api/users/me', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
        
    if 'name' in data and str(data['name']).strip() != "":
        user.name = data['name']
    if 'lastName' in data:
        user.lastName = data['lastName']
    if 'phone1' in data and str(data['phone1']).strip() != "":
        user.phone1 = data['phone1']
    if 'phone2' in data:
        user.phone2 = data['phone2']
        
    db.session.commit()
    return jsonify({'message': 'Perfil actualizado correctamente', 'user': user.to_dict()}), 200

@app.route('/api/users/email-change/request', methods=['POST'])
@jwt_required()
def request_email_change():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    user = User.query.get(current_user_id)
    
    if not data or not data.get('new_email'):
        return jsonify({'error': 'Debes proporcionar un nuevo correo válido'}), 400
        
    new_email = data['new_email'].strip()
    
    if User.query.filter_by(email=new_email).first() or User.query.filter_by(pending_email=new_email).first():
        return jsonify({'error': 'Este correo ya se encuentra registrado o en proceso de registro'}), 409

    otp_code = str(random.randint(100000, 999999))
    user.pending_email = new_email
    user.verification_code = otp_code
    db.session.commit()
    
    send_email_change_email(new_email, otp_code)
    return jsonify({'message': 'Código enviado al nuevo correo electrónico'}), 200

@app.route('/api/users/email-change/verify', methods=['POST'])
@jwt_required()
def verify_email_change():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    user = User.query.get(current_user_id)
    
    if not data or not data.get('code'):
        return jsonify({'error': 'Falta el código de verificación'}), 400
        
    if not user.pending_email:
        return jsonify({'error': 'No hay ninguna solicitud de cambio de correo pendiente'}), 400
        
    if user.verification_code != data['code']:
        return jsonify({'error': 'El código de verificación es incorrecto'}), 401
        
    # Aplicar el cambio
    user.email = user.pending_email
    user.pending_email = None
    user.verification_code = None
    db.session.commit()
    
    return jsonify({'message': 'Tu correo ha sido actualizado exitosamente'}), 200

# --- ENDPOINTS KYC Y S3 ---

@app.route('/api/kyc/update_pm', methods=['PUT'])
@jwt_required()
def update_payment_data():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or not all(k in data for k in ("pm_cedula", "pm_phone", "pm_bank")):
        return jsonify({'error': 'Faltan datos de pago móvil'}), 400

    user = User.query.get(current_user_id)
    user.pm_cedula = data['pm_cedula']
    user.pm_phone = data['pm_phone']
    user.pm_bank = data['pm_bank']
    
    if user.kyc_status == 'pending':
        user.kyc_status = 'in_progress'
        
    db.session.commit()
    return jsonify({'message': 'Datos de desembolso actualizados', 'user': user.to_dict()}), 200

@app.route('/api/kyc/guarantor', methods=['POST'])
@jwt_required()
def add_guarantor():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    data = request.get_json()

    required_fields = ['name', 'cedula', 'emergency_phone', 'email']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Datos del fiador incompletos'}), 400

    if len(user.guarantors) >= 2:
        return jsonify({'error': 'Ya has registrado el máximo de 2 fiadores'}), 400

    otp_code = str(random.randint(100000, 999999))
    
    new_guarantor = Guarantor(
        user_id=current_user_id,
        name=data['name'],
        cedula=data['cedula'],
        emergency_phone=data['emergency_phone'],
        email=data['email'],
        verification_code=otp_code
    )
    
    db.session.add(new_guarantor)
    db.session.commit()

    send_guarantor_email(new_guarantor.email, otp_code, f"{user.name} {user.lastName}")

    return jsonify({'message': 'Fiador registrado. Se ha enviado un código a su correo.', 'guarantor_id': new_guarantor.id}), 201

@app.route('/api/kyc/guarantor/verify', methods=['POST'])
@jwt_required()
def verify_guarantor():
    data = request.get_json()
    if not data or 'guarantor_id' not in data or 'code' not in data:
        return jsonify({'error': 'Faltan datos'}), 400

    guarantor = Guarantor.query.get(data['guarantor_id'])
    if not guarantor:
        return jsonify({'error': 'Fiador no encontrado'}), 404

    if guarantor.verification_code != data['code']:
        return jsonify({'error': 'Código incorrecto'}), 400

    guarantor.is_email_verified = True
    guarantor.verification_code = None
    
    user = User.query.get(guarantor.user_id)
    verified_guarantors = [g for g in user.guarantors if g.is_email_verified]
    
    if len(verified_guarantors) >= 2:
        user.kyc_status = 'verified'

    db.session.commit()
    return jsonify({'message': 'Fiador verificado exitosamente'}), 200

@app.route('/api/kyc/upload', methods=['POST'])
@jwt_required()
def upload_kyc_document():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    # --- LA MAGIA DEL CANDADO MENSUAL (30 DÍAS) ---
    # Si tiene fecha previa, verificamos si ha pasado el tiempo.
    # Permite ventana de 1 hora para poder subir los 4 documentos seguidos en la misma sesión.
    if user.last_kyc_update:
        time_since_update = datetime.utcnow() - user.last_kyc_update
        if timedelta(hours=1) < time_since_update < timedelta(days=30):
            return jsonify({'error': 'Solo puedes actualizar tus documentos KYC una vez cada 30 días.'}), 403
    # ----------------------------------------------
    
    if 'file' not in request.files or 'document_type' not in request.form:
        return jsonify({'error': 'Falta el archivo o el tipo de documento'}), 400
        
    file = request.files['file']
    doc_type = request.form['document_type'] 
    
    if file.filename == '':
        return jsonify({'error': 'Ningún archivo seleccionado'}), 400
        
    if file and allowed_file(file.filename):
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        filename = f"kyc/{current_user_id}/{doc_type}_{uuid.uuid4().hex[:8]}.{file_extension}"
        
        try:
            s3_client.upload_fileobj(
                file,
                S3_BUCKET,
                filename,
                ExtraArgs={"ContentType": file.content_type}
            )
            
            file_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{filename}"
            
            if doc_type == 'rif':
                user.rif_url = file_url
            elif doc_type == 'cedula_front':
                user.cedula_front_url = file_url
            elif doc_type == 'selfie':
                user.selfie_url = file_url
            elif doc_type == 'home':
                user.home_picture_url = file_url
            else:
                return jsonify({'error': 'Tipo de documento no válido'}), 400
                
            # Actualiza el reloj del candado de 30 días con cada subida
            user.last_kyc_update = datetime.utcnow()
            
            db.session.commit()
            return jsonify({'message': 'Archivo subido a S3 correctamente', 'url': file_url}), 200
            
        except NoCredentialsError:
            return jsonify({'error': 'Credenciales de AWS no válidas o no encontradas'}), 500
        except Exception as e:
            return jsonify({'error': f'Error subiendo a S3: {str(e)}'}), 500

    return jsonify({'error': 'Tipo de archivo no permitido'}), 400

# --- ENDPOINTS PROTEGIDOS (PERFIL Y PRÉSTAMOS) ---

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
    user = User.query.get(current_user_id)
    data = request.get_json()
    
    if user.kyc_status != 'verified':
        return jsonify({'error': 'Debes completar y verificar tu perfil KYC antes de solicitar un préstamo.'}), 403
        
    verified_guarantors = [g for g in user.guarantors if g.is_email_verified]
    if len(verified_guarantors) < 2:
        return jsonify({'error': 'Debes registrar y verificar los correos de al menos 2 fiadores solidarios.'}), 403

    if not data or 'amount' not in data or 'due_date' not in data:
        return jsonify({'error': 'Faltan datos del préstamo'}), 400
        
    try:
        date_str = data['due_date'].replace('Z', '+00:00')
        due_date = datetime.fromisoformat(date_str)
    except (KeyError, ValueError):
        return jsonify({'error': 'Formato de fecha inválido. Use ISO 8601.'}), 400

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