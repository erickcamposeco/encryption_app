from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from .models import db, User, EncryptionRecord
from .auth import AuthManager
from .encryption import EncryptionService
from config import Config
from datetime import datetime

bp = Blueprint('routes', __name__)

# Inicialización de servicios
auth_manager = AuthManager(Config.SECRET_KEY)
encryption_service = EncryptionService(Config.ENCRYPTION_KEY)

@bp.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('routes.dashboard'))
    return redirect(url_for('routes.login'))

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('routes.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if user and auth_manager.verify_password(user.password, password):
            login_user(user)
            return redirect(url_for('routes.dashboard'))
        
        flash('Usuario o contraseña incorrectos', 'error')
    return render_template('login.html')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if User.query.filter_by(username=username).first():
            flash('El usuario ya existe', 'error')
            return redirect(url_for('routes.register'))

        new_user = User(
            username=username,
            password=auth_manager.hash_password(password)
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registro exitoso. Por favor inicia sesión.', 'success')
        return redirect(url_for('routes.login'))
    
    return render_template('register.html')

@bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    active_tab = 'encrypt'  # Pestaña activa por defecto
    
    if request.method == 'POST':
        action = request.form.get('action')
        text = request.form.get('text', '').strip()
        token = request.form.get('token', '').strip()

        if action == 'encrypt' and text:
            try:
                encrypted_text = encryption_service.encrypt_text(text)
                access_token = encryption_service.generate_access_token(current_user.id, text)
                
                record = EncryptionRecord(
                    user_id=current_user.id,
                    original_text=text,
                    encrypted_text=encrypted_text,
                    token=access_token
                )
                db.session.add(record)
                db.session.commit()
                
                return render_template('dashboard.html',
                    encrypted_text=encrypted_text,
                    token=access_token,
                    active_tab=active_tab,
                    success='Texto encriptado correctamente')
            
            except Exception as e:
                flash(f'Error al encriptar: {str(e)}', 'error')

        elif action == 'decrypt' and token:
            active_tab = 'decrypt'  # Cambia a pestaña de desencriptar
            try:
                decrypted_data = encryption_service.decode_access_token(token)
                
                if not decrypted_data:
                    raise ValueError('Token inválido o corrupto')
                
                if decrypted_data['user_id'] != current_user.id:
                    raise PermissionError('No tienes permiso para desencriptar este token')
                
                # Registrar intento de desencriptación
                record = EncryptionRecord(
                    user_id=current_user.id,
                    original_text=decrypted_data['original_text'],
                    encrypted_text="[DECRYPT_ATTEMPT]",
                    token=token
                )
                db.session.add(record)
                db.session.commit()
                
                return render_template('dashboard.html',
                    decrypted_text=decrypted_data['original_text'],
                    token=token,
                    active_tab=active_tab,
                    success='Texto desencriptado correctamente')
            
            except Exception as e:
                flash(str(e), 'error')
                return render_template('dashboard.html',
                    token=token,
                    active_tab=active_tab)
    
    return render_template('dashboard.html', active_tab=active_tab)

@bp.route('/history')
@login_required
def history():
    records = EncryptionRecord.query.filter_by(
        user_id=current_user.id
    ).order_by(
        EncryptionRecord.created_at.desc()
    ).all()
    
    return render_template('history.html', records=records)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada correctamente', 'success')
    return redirect(url_for('routes.login'))