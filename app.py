import os
import uuid
import random
import smtplib
import requests  
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
from flask_cors import CORS
import boto3
from botocore.exceptions import NoCredentialsError
import google.generativeai as genai

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

# --- CONFIGURACIÓN IA (GEMINI) ---
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

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

# --- SEGURIDAD: LISTA BLANCA DE ADMINISTRADORES ---
# Solo estos correos tendrán acceso al portal web.
ADMIN_EMAILS = ['lodavidvera@gmail.com', 'jaycarvajal8@gmail.com', 'danperezc2003@gmail.com']

def is_admin(user):
    return user.email in ADMIN_EMAILS

# ==========================================
# MOTOR DE INTEGRACIÓN BNC (CON IP ESTÁTICA)
# ==========================================
def get_bnc_proxies():
    """ Enruta la salida a través de QuotaGuard para tener IP Estática frente al BNC """
    proxy_url = os.getenv('QUOTAGUARDSTATIC_URL')
    return {"http": proxy_url, "https": proxy_url} if proxy_url else None

def get_bnc_token():
    """
    Autentica con BNC usando Login/Password y devuelve el Token JWT temporal.
    """
    url = os.getenv('BNC_URL_AUTH')
    payload = {
        "Login": os.getenv('BNC_LOGIN'),
        "Password": os.getenv('BNC_PASSWORD')
    }
    try:
        response = requests.post(url, json=payload, proxies=get_bnc_proxies(), timeout=15)
        if response.status_code == 200:
            return response.text.strip()
        else:
            print(f"Error BNC Auth: {response.text}")
            return None
    except Exception as e:
        print(f"Excepción BNC Auth: {e}")
        return None


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
    
    last_kyc_update = db.Column(db.DateTime, nullable=True)
    pending_email = db.Column(db.String(120), nullable=True)
    
    pm_cedula = db.Column(db.String(50), nullable=True)
    pm_phone = db.Column(db.String(50), nullable=True)
    pm_bank = db.Column(db.String(100), nullable=True)
    
    loans = db.relationship('Loan', backref='user', lazy=True)
    payments = db.relationship('Payment', backref='user', lazy=True) 

    def to_dict(self):
        # MOTOR MATEMÁTICO: Calcula la deuda real iterando préstamos activos
        current_debt = sum(l.amount for l in self.loans if l.status == 'active')

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
            'current_debt': current_debt,
            'hasActiveLoan': current_debt > 0, 
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
            'is_admin': is_admin(self) 
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
    
    status = db.Column(db.String(20), default='active') 
    receipt_url = db.Column(db.String(255), nullable=True)
    
    # Campo añadido para cumplir normativa BNC de comprobantes
    bnc_reference = db.Column(db.String(100), nullable=True)
    
    payments = db.relationship('Payment', backref='loan', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'amount': self.amount,
            'interest_rate': self.interest_rate,
            'due_date': self.due_date.isoformat(),
            'status': self.status,
            'receipt_url': self.receipt_url,
            'bnc_reference': self.bnc_reference,
            'payment_history': [p.to_dict() for p in self.payments]
        }

class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.String(100), primary_key=True, default=lambda: str(uuid.uuid4()))
    loan_id = db.Column(db.String(100), db.ForeignKey('loans.id'), nullable=False)
    user_id = db.Column(db.String(100), db.ForeignKey('users.id'), nullable=False)
    
    amount = db.Column(db.Float, nullable=False, default=0.0)
    payment_method = db.Column(db.String(50), nullable=False)
    reference_number = db.Column(db.String(100), nullable=False)
    
    # Modificado a nullable=True porque los pagos C2P no llevan imagen
    receipt_url = db.Column(db.String(255), nullable=True)
    
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'loan_id': self.loan_id, 'amount': self.amount, 'method': self.payment_method,
            'reference': self.reference_number, 'receipt_url': self.receipt_url,
            'status': self.status, 'date': self.created_at.isoformat()
        }


# --- ENDPOINTS PÚBLICOS ---

@app.route('/', methods=['GET', 'HEAD'])
def home():
    return jsonify({"status": "Servidor Veyra activo y funcionando"}), 200

@app.route('/api/bcv-rate', methods=['GET'])
def get_bcv_rate():
    try:
        url = "https://ve.dolarapi.com/v1/dolares/oficial"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                "success": True, 
                "source": "BCV",
                "rate": data.get("promedio", 36.65),
                "date": data.get("fechaActualizacion", "")
            }), 200
        else:
            return jsonify({"success": True, "source": "Backup", "rate": 36.65}), 200
    except Exception as e:
        print(f"Error fetching BCV rate: {e}")
        return jsonify({"success": False, "error": str(e), "source": "Error", "rate": 36.65}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    required_fields = ['name', 'email', 'password', 'documentId', 'phone1']
    if not data: return jsonify({'error': 'No se enviaron datos JSON'}), 400
        
    for field in required_fields:
        if field not in data or str(data.get(field)).strip() == "":
            return jsonify({'error': f'El campo obligatorio "{field}" falta o está vacío'}), 400
            
    if User.query.filter_by(email=data['email']).first(): return jsonify({'error': 'El correo ya está registrado'}), 409
    if User.query.filter_by(documentId=data['documentId']).first(): return jsonify({'error': 'Esta cédula ya se encuentra registrada'}), 409

    phone1 = data['phone1'].strip()
    if User.query.filter_by(phone1=phone1).first() or User.query.filter_by(phone2=phone1).first(): return jsonify({'error': 'El teléfono principal ya está registrado en otra cuenta'}), 409
        
    phone2 = data.get('phone2', '').strip()
    if phone2 != "":
        if User.query.filter_by(phone1=phone2).first() or User.query.filter_by(phone2=phone2).first():
            return jsonify({'error': 'El teléfono secundario ya está registrado en otra cuenta'}), 409

    otp_code = str(random.randint(100000, 999999))

    new_user = User(
        name=data['name'], lastName=data.get('lastName', ''), documentId=data['documentId'],
        phone1=phone1, phone2=phone2, email=data['email'], is_verified=False, verification_code=otp_code
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
    if not data or not data.get('email') or not data.get('code'): return jsonify({'error': 'Faltan datos de verificación'}), 400
        
    user = User.query.filter_by(email=data['email']).first()
    if not user: return jsonify({'error': 'Usuario no encontrado'}), 404
    if user.is_verified: return jsonify({'message': 'La cuenta ya estaba verificada'}), 200
    if user.verification_code != data['code']: return jsonify({'error': 'El código de verificación es incorrecto'}), 401
        
    user.is_verified = True
    user.verification_code = None 
    db.session.commit()
    return jsonify({'message': 'Cuenta verificada exitosamente'}), 200

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'): return jsonify({'error': 'Credenciales incompletas'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user or not user.check_password(data['password']): return jsonify({'error': 'Correo o contraseña incorrectos'}), 401

    if not user.is_verified: return jsonify({'error': 'Debes verificar tu correo electrónico antes de iniciar sesión', 'needs_verification': True}), 403

    access_token = create_access_token(identity=user.id)
    return jsonify({'token': access_token, 'user': user.to_dict()}), 200

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data or not data.get('email'): return jsonify({'error': 'Falta el correo'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user: return jsonify({'error': 'No existe una cuenta con este correo'}), 404

    otp_code = str(random.randint(100000, 999999))
    user.verification_code = otp_code
    db.session.commit()

    send_reset_email(user.email, otp_code)
    return jsonify({'message': 'Código enviado'}), 200

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('code') or not data.get('new_password'): return jsonify({'error': 'Datos incompletos'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user or user.verification_code != data['code']: return jsonify({'error': 'Código inválido o expirado'}), 401

    user.set_password(data['new_password'])
    user.verification_code = None
    db.session.commit()

    return jsonify({'message': 'Contraseña actualizada'}), 200

# --- EDICIÓN DE PERFIL Y CAMBIO DE CORREO ---
@app.route('/api/users/me', methods=['GET'])
@jwt_required()
def get_my_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user: return jsonify({'error': 'Usuario no encontrado'}), 404
    return jsonify(user.to_dict()), 200

@app.route('/api/users/me', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    user = User.query.get(current_user_id)
    
    if not user: return jsonify({'error': 'Usuario no encontrado'}), 404
        
    if 'name' in data and str(data['name']).strip() != "": user.name = data['name']
    if 'lastName' in data: user.lastName = data['lastName']
    if 'phone1' in data and str(data['phone1']).strip() != "": user.phone1 = data['phone1']
    if 'phone2' in data: user.phone2 = data['phone2']
        
    db.session.commit()
    return jsonify({'message': 'Perfil actualizado correctamente', 'user': user.to_dict()}), 200

@app.route('/api/users/email-change/request', methods=['POST'])
@jwt_required()
def request_email_change():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    user = User.query.get(current_user_id)
    
    if not data or not data.get('new_email'): return jsonify({'error': 'Debes proporcionar un nuevo correo válido'}), 400
        
    new_email = data['new_email'].strip()
    
    if User.query.filter_by(email=new_email).first() or User.query.filter_by(pending_email=new_email).first(): return jsonify({'error': 'Este correo ya se encuentra registrado o en proceso de registro'}), 409

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
    
    if not data or not data.get('code'): return jsonify({'error': 'Falta el código de verificación'}), 400
    if not user.pending_email: return jsonify({'error': 'No hay ninguna solicitud de cambio de correo pendiente'}), 400
    if user.verification_code != data['code']: return jsonify({'error': 'El código de verificación es incorrecto'}), 401
        
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
    
    if not data or not all(k in data for k in ("pm_cedula", "pm_phone", "pm_bank")): return jsonify({'error': 'Faltan datos de pago móvil'}), 400

    user = User.query.get(current_user_id)
    user.pm_cedula = data['pm_cedula']
    user.pm_phone = data['pm_phone']
    user.pm_bank = data['pm_bank']
    
    if user.kyc_status in ['pending', 'in_progress']: 
        user.kyc_status = 'pending_admin'
        
    db.session.commit()
    return jsonify({'message': 'Datos de desembolso actualizados y perfil en revisión administrativa', 'user': user.to_dict()}), 200

@app.route('/api/kyc/upload', methods=['POST'])
@jwt_required()
def upload_kyc_document():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user.last_kyc_update:
        time_since_update = datetime.utcnow() - user.last_kyc_update
        if timedelta(hours=1) < time_since_update < timedelta(days=30):
            return jsonify({'error': 'Solo puedes actualizar tus documentos KYC una vez cada 30 días.'}), 403
    
    if 'file' not in request.files or 'document_type' not in request.form: return jsonify({'error': 'Falta el archivo o el tipo de documento'}), 400
        
    file = request.files['file']
    doc_type = request.form['document_type'] 
    
    if file.filename == '': return jsonify({'error': 'Ningún archivo seleccionado'}), 400
        
    if file and allowed_file(file.filename):
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        filename = f"kyc/{current_user_id}/{doc_type}_{uuid.uuid4().hex[:8]}.{file_extension}"
        
        try:
            s3_client.upload_fileobj(file, S3_BUCKET, filename, ExtraArgs={"ContentType": file.content_type})
            file_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{filename}"
            
            if doc_type == 'rif': user.rif_url = file_url
            elif doc_type == 'cedula_front': user.cedula_front_url = file_url
            elif doc_type == 'selfie': user.selfie_url = file_url
            elif doc_type == 'home': user.home_picture_url = file_url
            else: return jsonify({'error': 'Tipo de documento no válido'}), 400
                
            user.last_kyc_update = datetime.utcnow()
            
            if user.kyc_status == 'pending':
                user.kyc_status = 'in_progress'

            db.session.commit()
            return jsonify({'message': 'Archivo subido a S3 correctamente', 'url': file_url}), 200
            
        except NoCredentialsError:
            return jsonify({'error': 'Credenciales de AWS no válidas o no encontradas'}), 500
        except Exception as e:
            return jsonify({'error': f'Error subiendo a S3: {str(e)}'}), 500

    return jsonify({'error': 'Tipo de archivo no permitido'}), 400

# ==========================================
# PRÉSTAMOS ROTATIVOS (Desembolso BNC Automatizado)
# ==========================================
@app.route('/api/loans', methods=['POST'])
@jwt_required()
def create_loan():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    data = request.get_json()
    
    if user.kyc_status != 'verified':
        return jsonify({'error': 'Debes completar tu perfil y esperar aprobación administrativa antes de solicitar un préstamo.'}), 403

    if not data or 'amount' not in data or 'due_date' not in data: return jsonify({'error': 'Faltan datos del préstamo'}), 400
        
    try:
        requested_amount = float(data['amount'])
        date_str = data['due_date'].replace('Z', '+00:00')
        due_date = datetime.fromisoformat(date_str)
    except (KeyError, ValueError): return jsonify({'error': 'Formato de fecha o monto inválido.'}), 400

    if not user: return jsonify({'error': 'Usuario inválido'}), 404

    current_debt = sum(l.amount for l in user.loans if l.status == 'active')
    if current_debt + requested_amount > user.maxCreditAllowed:
        return jsonify({'error': 'Fondos insuficientes. Límite de crédito excedido.'}), 400

    if not user.pm_phone or not user.pm_bank or not user.pm_cedula:
        return jsonify({'error': 'No tienes configurados los datos de Pago Móvil para recibir el dinero.'}), 400

    # 1. Solicitar Token BNC
    bnc_token = get_bnc_token()
    if not bnc_token:
        return jsonify({'error': 'Servicio interbancario no disponible temporalmente. Intente más tarde.'}), 503

    # 2. Ejecutar Emisión de Pago Móvil en BNC agregando el proxy de salida
    emision_url = os.getenv('BNC_URL_EMISION')
    emision_payload = {
        "monto": requested_amount,
        "telefono_destino": user.pm_phone,
        "cedula_destino": user.pm_cedula,
        "banco_destino": user.pm_bank,
        "concepto": f"Desembolso Veyra"
    }
    headers = {"Authorization": f"Bearer {bnc_token}"}
    
    try:
        response = requests.post(emision_url, json=emision_payload, headers=headers, proxies=get_bnc_proxies(), timeout=15)
        bnc_data = response.json()
        
        # 3. Validar si el banco procesó el pago con éxito
        if response.status_code == 200 and bnc_data.get('codigoRespuesta') == '00':
            new_loan = Loan(
                user_id=current_user_id, amount=requested_amount, 
                interest_rate=float(data.get('interest_rate', 0.15)), 
                due_date=due_date,
                bnc_reference=bnc_data.get('referencia', 'REF-GENERADA')
            )
            user.hasActiveLoan = True
            db.session.add(new_loan)
            db.session.commit()
            return jsonify(new_loan.to_dict()), 201
        else:
            return jsonify({'error': f"Rechazo bancario: {bnc_data.get('mensajeError', 'Desconocido')}"}), 400

    except Exception as e:
        return jsonify({'error': f'Falla de conexión con la red interbancaria: {str(e)}'}), 500


@app.route('/api/loans/me', methods=['GET'])
@jwt_required()
def get_my_loans():
    current_user_id = get_jwt_identity()
    loans = Loan.query.filter_by(user_id=current_user_id).all()
    return jsonify([loan.to_dict() for loan in loans]), 200

# ==========================================
# COBRO AUTOMATIZADO (C2P BNC)
# ==========================================
@app.route('/api/loans/pay/c2p', methods=['POST'])
@jwt_required()
def process_c2p_payment():
    """ Nuevo endpoint 100% automatizado mediante C2P """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    data = request.get_json()
    
    amount_paid = float(data.get('amount', 0))
    token_c2p = data.get('token_c2p') # Clave generada por el usuario en su banco
    banco_origen = data.get('bank')
    telefono_origen = data.get('phone')
    cedula_origen = data.get('cedula')

    if not all([amount_paid, token_c2p, banco_origen, telefono_origen, cedula_origen]):
        return jsonify({'error': 'Faltan datos (Monto, Banco, Cédula, Teléfono o Token C2P)'}), 400

    bnc_token = get_bnc_token()
    if not bnc_token: return jsonify({'error': 'Error interno de autenticación bancaria.'}), 503

    c2p_url = os.getenv('BNC_URL_C2P')
    c2p_payload = {
        "monto": amount_paid,
        "telefono_origen": telefono_origen,
        "cedula_origen": cedula_origen,
        "banco_origen": banco_origen,
        "token_c2p": token_c2p
    }
    headers = {"Authorization": f"Bearer {bnc_token}"}

    try:
        response = requests.post(c2p_url, json=c2p_payload, headers=headers, proxies=get_bnc_proxies(), timeout=15)
        bnc_data = response.json()
        
        if response.status_code == 200 and bnc_data.get('codigoRespuesta') == '00':
            referencia_bnc = bnc_data.get('referencia', f'C2P-{int(datetime.utcnow().timestamp())}')
            
            loan = Loan.query.filter_by(user_id=current_user_id, status='active').order_by(Loan.due_date).first()
            if not loan: return jsonify({'error': 'Transacción exitosa, pero no se encontró préstamo activo.'}), 400

            new_payment = Payment(
                loan_id=loan.id, user_id=user.id, amount=amount_paid, 
                payment_method='C2P BNC', reference_number=referencia_bnc, 
                status='approved', receipt_url=None
            )
            db.session.add(new_payment)
            
            amount_to_apply = amount_paid
            active_loans = Loan.query.filter_by(user_id=user.id, status='active').order_by(Loan.due_date).all()
            for l in active_loans:
                if amount_to_apply <= 0: break
                if l.amount <= amount_to_apply:
                    amount_to_apply -= l.amount
                    l.amount = 0
                    l.status = 'liquidated'
                else:
                    l.amount -= amount_to_apply
                    amount_to_apply = 0
                    
            if sum(l.amount for l in user.loans if l.status == 'active') <= 0:
                user.hasActiveLoan = False 
                
            db.session.commit()
            return jsonify({'message': 'Cobro procesado exitosamente. Deuda liquidada.', 'referencia': referencia_bnc}), 200
        else:
            return jsonify({'error': f"El banco rechazó el cobro: {bnc_data.get('mensajeError', 'Token inválido o fondos insuficientes')}"}), 400

    except Exception as e:
        return jsonify({'error': f'Falla de conexión interbancaria: {str(e)}'}), 500

# ==========================================
# REPORTE DE PAGO MANUAL (Mantenido intacto para S3)
# ==========================================
@app.route('/api/loans/pay', methods=['POST'])
@jwt_required()
def report_payment():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user: return jsonify({'error': 'Usuario no encontrado'}), 404
    
    current_debt = sum(l.amount for l in user.loans if l.status == 'active')
    if current_debt <= 0: return jsonify({'error': 'No tienes deudas activas para pagar'}), 400
    
    if 'file' not in request.files: return jsonify({'error': 'Falta el comprobante de pago'}), 400
        
    file = request.files['file']
    payment_method = request.form.get('payment_method', 'transferencia')
    reference_number = request.form.get('reference_number', '')
    
    try:
        amount_paid = float(request.form.get('amount', 0))
    except ValueError:
        return jsonify({'error': 'Monto inválido'}), 400
        
    if amount_paid <= 0:
        return jsonify({'error': 'El monto a pagar debe ser mayor a 0'}), 400
    
    if file.filename == '': return jsonify({'error': 'Ningún archivo seleccionado'}), 400
        
    if file and allowed_file(file.filename):
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        filename = f"payments/{current_user_id}/receipt_{uuid.uuid4().hex[:8]}.{file_extension}"
        
        try:
            s3_client.upload_fileobj(file, S3_BUCKET, filename, ExtraArgs={"ContentType": file.content_type})
            receipt_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{filename}"
            
            loan = Loan.query.filter_by(user_id=current_user_id, status='active').order_by(Loan.due_date).first()
            if loan:
                new_payment = Payment(
                    loan_id=loan.id,
                    user_id=user.id,
                    amount=amount_paid,
                    payment_method=payment_method,
                    reference_number=reference_number,
                    receipt_url=receipt_url
                )
                db.session.add(new_payment)
            
            db.session.commit()
            return jsonify({'message': 'Pago reportado con éxito. En revisión administrativa.', 'receipt_url': receipt_url}), 200
            
        except NoCredentialsError: return jsonify({'error': 'Credenciales de AWS no válidas'}), 500
        except Exception as e: return jsonify({'error': f'Error subiendo comprobante: {str(e)}'}), 500

    return jsonify({'error': 'Tipo de archivo no permitido'}), 400


# ==========================================
# WEBHOOK BNC OBLIGATORIO (Notificaciones SNP)
# ==========================================
@app.route('/api/bnc/auth', methods=['POST'])
@app.route('/api/bnc/dev/auth', methods=['POST'])
def bnc_webhook_auth():
    """ 
    Ruta requerida por el Formulario SNP. 
    BNC consumirá esto para obtener permiso de enviarte notificaciones.
    """
    data = request.get_json() or {}
    
    if data.get("Login") == "VeyraBNC" and data.get("Password") == "VeyraBNC2026*":
        token = create_access_token(identity="bnc_system", expires_delta=timedelta(days=365))
        return token, 200
        
    return "No autorizado", 401

@app.route('/api/bnc/webhook', methods=['POST'])
@app.route('/api/bnc/dev/webhook', methods=['POST'])
@jwt_required()
def bnc_webhook():
    """ 
    Ruta donde BNC envía los pagos recibidos pasivamente.
    El header debe traer: Authorization: Bearer <token>
    """
    if get_jwt_identity() != "bnc_system":
        return jsonify({"error": "Acceso denegado"}), 403
        
    data = request.get_json()
    return jsonify({"status": "Recibido"}), 200


# ==========================================
# ENDPOINT DE INTELIGENCIA ARTIFICIAL (SOPORTE BNC)
# ==========================================
@app.route('/api/chat_soporte', methods=['POST'])
@jwt_required()
def chat_soporte():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    data = request.get_json()
    
    if not data or not data.get('message'):
        return jsonify({'error': 'Mensaje vacío'}), 400
        
    user_message = data['message']
    current_debt = sum(l.amount for l in user.loans if l.status == 'active')
    
    # -------------------------------------------------------------
    # MEJORA DEL CEREBRO DE LA IA: Guía interactiva y tiempo real
    # -------------------------------------------------------------
    hoy_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
    
    system_prompt = f"""
    Eres el asistente virtual experto de 'Veyra Money', la app financiera de THE JAYDI'S C.A.
    Tu objetivo es guiar a los usuarios dentro de la aplicación, resolver dudas sobre sus cuentas y ayudar con errores de pagos (especialmente BNC).
    
    Contexto del usuario actual:
    - Nombre: {user.name}
    - Deuda actual: ${current_debt}
    - Límite de crédito total: ${user.maxCreditAllowed}
    - Estado KYC (Verificación): {user.kyc_status}
    - Fecha y hora actual del servidor: {hoy_str}
    
    Reglas de comportamiento y resolución (MUY IMPORTANTE):
    1. Eres un empleado de THE JAYDI'S C.A., nunca digas que eres una IA de Google o Gemini.
    2. NO TIENES PERMISO para ejecutar acciones (no puedes aprobar préstamos, ni procesar pagos, ni cambiar datos). Eres un asesor que orienta al cliente sobre cómo hacerlo él mismo en la app.
    3. SI PIDEN UN PRÉSTAMO: Diles su límite actual, y explícales paso a paso que deben volver atrás, tocar la pestaña "Inicio", usar la barra deslizante (slider) azul para elegir el monto, y presionar el botón "CONFIRMAR PRÉSTAMO".
    4. SI QUIEREN PAGAR: Diles su deuda actual y guíalos a volver atrás y tocar la pestaña "Pagos", indicando que pueden usar el débito automático "Pago Móvil C2P BNC" ingresando su token bancario.
    5. ERRORES C2P: Recuerda que los tokens del BNC expiran el mismo día a las 11:59 PM. Si hay fondos insuficientes, diles que revisen su app del BNC.
    6. KYC: Si su estado es 'pending' o 'pending_admin', recuérdales que no pueden pedir créditos hasta que el equipo de soporte apruebe sus documentos.
    7. Sé siempre empático, claro, directo y responde en el mismo idioma o tono del usuario.
    """
    
    try:
        # CORRECCIÓN TÉCNICA: Se actualizó el modelo a latest para evitar el error 404
        model = genai.GenerativeModel(
            'gemini-1.5-flash-latest', 
            system_instruction=system_prompt,
            generation_config={"temperature": 0.3} 
        )
        response = model.generate_content(user_message)
        return jsonify({'reply': response.text}), 200
    except Exception as e:
        print(f"Error AI: {e}")
        return jsonify({'error': 'Nuestro sistema de soporte automático está saturado. Intenta de nuevo en unos minutos.'}), 500


# ==========================================
# RUTAS DE ADMINISTRACIÓN (BACKOFFICE)
# ==========================================

@app.route('/api/admin/users/all', methods=['GET'])
@jwt_required()
def get_all_users_admin():
    admin = User.query.get(get_jwt_identity())
    if not admin or not is_admin(admin): 
        return jsonify({'error': 'Acceso Administrativo Denegado'}), 403

    all_users = User.query.order_by(User.name).all()
    
    users_data = []
    for u in all_users:
        user_dict = u.to_dict()
        
        user_loans = Loan.query.filter_by(user_id=u.id).order_by(Loan.due_date.desc()).all()
        user_dict['loan_history'] = [l.to_dict() for l in user_loans]
        
        user_payments = Payment.query.filter_by(user_id=u.id).order_by(Payment.created_at.desc()).all()
        user_dict['payment_history'] = [p.to_dict() for p in user_payments]
        
        users_data.append(user_dict)

    return jsonify({'users': users_data}), 200

@app.route('/api/admin/dashboard', methods=['GET'])
@jwt_required()
def admin_dashboard():
    user = User.query.get(get_jwt_identity())
    if not user or not is_admin(user): return jsonify({'error': 'Acceso Administrativo Denegado'}), 403

    pending_kyc = User.query.filter_by(kyc_status='pending_admin').all()
    pending_payments = Payment.query.filter_by(status='pending').all()
    overdue_loans = Loan.query.filter(Loan.status == 'active', Loan.due_date < datetime.utcnow()).all()

    return jsonify({
        'pending_kyc_users': [u.to_dict() for u in pending_kyc],
        'pending_payments': [{'payment': p.to_dict(), 'user': User.query.get(p.user_id).to_dict(), 'loan': Loan.query.get(p.loan_id).to_dict()} for p in pending_payments],
        'overdue_loans': [l.to_dict() for l in overdue_loans]
    }), 200

@app.route('/api/admin/users/<user_id>/review_kyc', methods=['POST'])
@jwt_required()
def review_kyc(user_id):
    admin = User.query.get(get_jwt_identity())
    if not admin or not is_admin(admin): return jsonify({'error': 'Acceso Denegado'}), 403
    
    data = request.get_json()
    action = data.get('action') 
    
    target_user = User.query.get(user_id)
    if not target_user: return jsonify({'error': 'Usuario no encontrado'}), 404
    
    if action == 'approve':
        target_user.kyc_status = 'verified'
        msg = f"Identidad de {target_user.name} aprobada. Límite habilitado."
    else:
        target_user.kyc_status = 'rejected'
        msg = f"Identidad de {target_user.name} rechazada."
        
    db.session.commit()
    return jsonify({'message': msg}), 200

@app.route('/api/admin/payments/<payment_id>/review', methods=['POST'])
@jwt_required()
def review_payment(payment_id):
    admin = User.query.get(get_jwt_identity())
    if not admin or not is_admin(admin): return jsonify({'error': 'Acceso Denegado'}), 403
    
    data = request.get_json()
    action = data.get('action') 
    
    payment = Payment.query.get(payment_id)
    if not payment: return jsonify({'error': 'Pago no encontrado'}), 404
    
    user = User.query.get(payment.user_id)
    
    if action == 'approve':
        payment.status = 'approved'
        amount_to_apply = payment.amount
        
        active_loans = Loan.query.filter_by(user_id=user.id, status='active').order_by(Loan.due_date).all()
        for loan in active_loans:
            if amount_to_apply <= 0: 
                break
                
            if loan.amount <= amount_to_apply:
                amount_to_apply -= loan.amount
                loan.amount = 0
                loan.status = 'liquidated'
            else:
                loan.amount -= amount_to_apply
                amount_to_apply = 0
                
        remaining_debt = sum(l.amount for l in user.loans if l.status == 'active')
        if remaining_debt <= 0:
            user.hasActiveLoan = False 
            
        msg = f"Abono de ${payment.amount} liquidado. Deuda restante del cliente: ${remaining_debt}"
    else:
        payment.status = 'rejected'
        msg = "Recibo rechazado. La deuda se mantiene igual."
        
    db.session.commit()
    return jsonify({'message': msg}), 200

@app.route('/api/admin/cron/morosidad', methods=['POST'])
@jwt_required()
def trigger_morosidad():
    admin = User.query.get(get_jwt_identity())
    if not admin or not is_admin(admin): return jsonify({'error': 'Acceso Denegado'}), 403
    
    hoy = datetime.utcnow()
    expired_loans = Loan.query.filter(Loan.status == 'active', Loan.due_date < hoy).all()
    
    for loan in expired_loans:
        penalidad = loan.amount * 0.10 
        loan.amount += penalidad
        loan.due_date = loan.due_date + timedelta(days=3)
        
    db.session.commit()
    return jsonify({'message': f'Penalización de mora aplicada a {len(expired_loans)} deudores.'}), 200

# ==========================================
# RUTAS WEB (FRONTEND FLASK)
# ==========================================
@app.route('/backoffice', methods=['GET'])
def render_backoffice():
    return render_template('admin_dashboard.html')

@app.route('/privacidad', methods=['GET'])
def politicas_privacidad():
    return render_template('privacidad.html')

# Inicialización de la base de datos
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)