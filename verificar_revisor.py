from app import app, db, User

with app.app_context():
    # Buscar al usuario por el correo
    revisor = User.query.filter_by(email='revisorgoogle@veyramoney.com').first()
    
    if revisor:
        # 1. Bypass del OTP (Verificación de correo)
        revisor.is_verified = True
        revisor.verification_code = None
        
        # 2. Bypass del KYC (Aprobar identidad para que vea los préstamos)
        revisor.kyc_status = 'verified'
        
        # 3. Asignar un límite de crédito de prueba
        revisor.creditLevel = 2
        revisor.maxCreditAllowed = 100.0
        
        db.session.commit()
        print("Éxito: La cuenta del revisor de Google ha sido verificada y el KYC aprobado.")
    else:
        print("Error: No se encontró la cuenta. Regístrala primero en la app.")