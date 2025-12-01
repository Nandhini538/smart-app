"""
Smart Home Application - app.py
A complete smart home automation system with device control, scheduling, and automation rules
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import os
import pytz
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import time
import logging

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'smart-app-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///smart_home.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# ----------------- MODELS -----------------

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(200), default='default.jpg')
    
    # Relationships
    devices = db.relationship('Device', backref='owner', lazy=True)
    automations = db.relationship('Automation', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat()
        }

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    device_id = db.Column(db.String(50), unique=True, nullable=False)
    device_type = db.Column(db.String(50), nullable=False)  # light, thermostat, camera, plug, sensor
    status = db.Column(db.Boolean, default=False)
    power_consumption = db.Column(db.Float, default=0.0)  # in watts
    settings = db.Column(db.Text, default='{}')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    room = db.Column(db.String(50), default='Living Room')
    ip_address = db.Column(db.String(45))
    firmware_version = db.Column(db.String(20), default='1.0.0')
    
    @property
    def settings_dict(self):
        return json.loads(self.settings)
    
    @settings_dict.setter
    def settings_dict(self, value):
        self.settings = json.dumps(value)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'device_id': self.device_id,
            'device_type': self.device_type,
            'status': self.status,
            'power_consumption': self.power_consumption,
            'settings': self.settings_dict,
            'last_seen': self.last_seen.isoformat(),
            'room': self.room,
            'ip_address': self.ip_address,
            'firmware_version': self.firmware_version
        }

class Automation(db.Model):
    __tablename__ = 'automations'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    trigger_type = db.Column(db.String(50), nullable=False)  # time, sensor, manual
    trigger_value = db.Column(db.String(200))
    action_type = db.Column(db.String(50), nullable=False)  # toggle, set_value, notify
    action_value = db.Column(db.String(200))
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    device = db.relationship('Device')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'trigger_type': self.trigger_type,
            'trigger_value': self.trigger_value,
            'action_type': self.action_type,
            'action_value': self.action_value,
            'device_id': self.device_id,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat()
        }

class DeviceLog(db.Model):
    __tablename__ = 'device_logs'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    old_value = db.Column(db.String(200))
    new_value = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    triggered_by = db.Column(db.String(50))  # user, automation, system
    
    device = db.relationship('Device')

class EnergyUsage(db.Model):
    __tablename__ = 'energy_usage'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    watt_hours = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cost = db.Column(db.Float, default=0.0)  # calculated cost
    
    device = db.relationship('Device')

# ----------------- AUTHENTICATION -----------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------- HELPER FUNCTIONS -----------------

def log_device_action(device_id, action, old_value=None, new_value=None, triggered_by='user'):
    """Log device actions for audit trail"""
    log = DeviceLog(
        device_id=device_id,
        action=action,
        old_value=str(old_value) if old_value else None,
        new_value=str(new_value) if new_value else None,
        triggered_by=triggered_by
    )
    db.session.add(log)
    db.session.commit()
    
    # Notify via WebSocket
    socketio.emit('device_log', {
        'device_id': device_id,
        'action': action,
        'timestamp': datetime.utcnow().isoformat(),
        'triggered_by': triggered_by
    })

def update_energy_usage(device_id, watts, duration_hours=1):
    """Update energy usage for a device"""
    watt_hours = watts * duration_hours
    cost = watt_hours * 0.00012  # Example rate: $0.12 per kWh
    
    usage = EnergyUsage(
        device_id=device_id,
        watt_hours=watt_hours,
        cost=cost
    )
    db.session.add(usage)
    db.session.commit()

def check_and_run_automations(trigger_type, trigger_value=None, device_id=None):
    """Check and run automations based on trigger"""
    automations = Automation.query.filter_by(
        trigger_type=trigger_type,
        is_active=True
    ).all()
    
    for automation in automations:
        if (trigger_value and automation.trigger_value == trigger_value) or not trigger_value:
            execute_automation(automation)

def execute_automation(automation):
    """Execute an automation rule"""
    try:
        device = Device.query.get(automation.device_id)
        if not device:
            return
        
        if automation.action_type == 'toggle':
            device.status = not device.status
            action = 'toggled'
        elif automation.action_type == 'turn_on':
            device.status = True
            action = 'turned on'
        elif automation.action_type == 'turn_off':
            device.status = False
            action = 'turned off'
        elif automation.action_type == 'set_value':
            # For devices with settings (like thermostats)
            settings = device.settings_dict
            settings.update(json.loads(automation.action_value))
            device.settings_dict = settings
            action = f'settings updated: {automation.action_value}'
        
        db.session.commit()
        
        # Log the automation action
        log_device_action(
            device.id,
            f'Automation executed: {automation.name}',
            triggered_by='automation'
        )
        
        # Notify via WebSocket
        socketio.emit('device_update', {
            'device_id': device.id,
            'status': device.status,
            'settings': device.settings_dict,
            'automation': automation.name
        })
        
        logger.info(f"Automation '{automation.name}' executed on device '{device.name}'")
        
    except Exception as e:
        logger.error(f"Error executing automation {automation.id}: {str(e)}")

# ----------------- ROUTES -----------------

@app.route('/')
def index():
    """Home page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    devices = Device.query.filter_by(user_id=current_user.id).all()
    total_devices = len(devices)
    active_devices = sum(1 for d in devices if d.status)
    
    # Calculate total power consumption
    total_power = sum(d.power_consumption for d in devices if d.status)
    
    # Get recent logs
    recent_logs = DeviceLog.query.join(Device).filter(
        Device.user_id == current_user.id
    ).order_by(DeviceLog.timestamp.desc()).limit(10).all()
    
    return render_template('dashboard.html',
                         devices=devices,
                         total_devices=total_devices,
                         active_devices=active_devices,
                         total_power=total_power,
                         recent_logs=recent_logs)

@app.route('/api/devices', methods=['GET'])
@login_required
def get_devices():
    """Get all devices for current user"""
    devices = Device.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'success': True,
        'devices': [device.to_dict() for device in devices]
    })

@app.route('/api/device', methods=['POST'])
@login_required
def add_device():
    """Add a new device"""
    try:
        data = request.json
        device = Device(
            name=data['name'],
            device_id=data.get('device_id', f"device_{datetime.utcnow().timestamp()}"),
            device_type=data['device_type'],
            user_id=current_user.id,
            room=data.get('room', 'Living Room'),
            ip_address=data.get('ip_address'),
            firmware_version=data.get('firmware_version', '1.0.0')
        )
        db.session.add(device)
        db.session.commit()
        
        log_device_action(device.id, 'Device added')
        
        return jsonify({
            'success': True,
            'message': 'Device added successfully',
            'device': device.to_dict()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/device/<int:device_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def device_operations(device_id):
    """Device operations (GET, UPDATE, DELETE)"""
    device = Device.query.get_or_404(device_id)
    
    # Check ownership
    if device.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'device': device.to_dict()
        })
    
    elif request.method == 'PUT':
        try:
            data = request.json
            old_status = device.status
            
            # Update fields
            if 'name' in data:
                device.name = data['name']
            if 'status' in data:
                device.status = data['status']
                
                # Log status change
                if old_status != device.status:
                    action = 'turned on' if device.status else 'turned off'
                    log_device_action(device.id, f'Device {action}', old_status, device.status)
                    
                    # Update energy usage if device was on
                    if old_status and not device.status:
                        update_energy_usage(device.id, device.power_consumption, 0.5)  # Assume 0.5 hours
            
            if 'settings' in data:
                device.settings_dict = data['settings']
                log_device_action(device.id, 'Settings updated', device.settings_dict, data['settings'])
            
            if 'room' in data:
                device.room = data['room']
            
            device.last_seen = datetime.utcnow()
            db.session.commit()
            
            # Notify via WebSocket
            socketio.emit('device_update', {
                'device_id': device.id,
                'status': device.status,
                'settings': device.settings_dict,
                'room': device.room
            })
            
            return jsonify({
                'success': True,
                'message': 'Device updated',
                'device': device.to_dict()
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
    
    elif request.method == 'DELETE':
        log_device_action(device.id, 'Device removed')
        db.session.delete(device)
        db.session.commit()
        
        socketio.emit('device_removed', {'device_id': device_id})
        
        return jsonify({'success': True, 'message': 'Device deleted'})

@app.route('/api/device/<int:device_id>/toggle', methods=['POST'])
@login_required
def toggle_device(device_id):
    """Toggle device status"""
    device = Device.query.get_or_404(device_id)
    
    if device.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    old_status = device.status
    device.status = not device.status
    device.last_seen = datetime.utcnow()
    db.session.commit()
    
    action = 'turned on' if device.status else 'turned off'
    log_device_action(device.id, f'Device {action}', old_status, device.status)
    
    # Update energy usage
    if old_status and not device.status:
        update_energy_usage(device.id, device.power_consumption, 0.5)
    
    # Check for automations triggered by device status change
    check_and_run_automations('device_status', str(device.status), device.id)
    
    # Notify via WebSocket
    socketio.emit('device_update', {
        'device_id': device.id,
        'status': device.status,
        'action': 'toggled'
    })
    
    return jsonify({
        'success': True,
        'message': f'Device {action}',
        'device': device.to_dict()
    })

@app.route('/api/automations', methods=['GET', 'POST'])
@login_required
def automations():
    """Get or create automations"""
    if request.method == 'GET':
        automations_list = Automation.query.filter_by(user_id=current_user.id).all()
        return jsonify({
            'success': True,
            'automations': [auto.to_dict() for auto in automations_list]
        })
    
    elif request.method == 'POST':
        try:
            data = request.json
            automation = Automation(
                name=data['name'],
                trigger_type=data['trigger_type'],
                trigger_value=data.get('trigger_value'),
                action_type=data['action_type'],
                action_value=data.get('action_value'),
                device_id=data.get('device_id'),
                user_id=current_user.id,
                is_active=data.get('is_active', True)
            )
            db.session.add(automation)
            db.session.commit()
            
            # If it's a time-based automation, schedule it
            if automation.trigger_type == 'time' and automation.is_active:
                schedule_automation(automation)
            
            return jsonify({
                'success': True,
                'message': 'Automation created',
                'automation': automation.to_dict()
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

def schedule_automation(automation):
    """Schedule a time-based automation"""
    try:
        # Parse time from trigger_value (format: "HH:MM" or cron expression)
        if ':' in automation.trigger_value:
            hour, minute = map(int, automation.trigger_value.split(':'))
            scheduler.add_job(
                execute_automation,
                'cron',
                hour=hour,
                minute=minute,
                args=[automation],
                id=f'automation_{automation.id}'
            )
    except Exception as e:
        logger.error(f"Error scheduling automation {automation.id}: {str(e)}")

@app.route('/api/energy/usage', methods=['GET'])
@login_required
def get_energy_usage():
    """Get energy usage statistics"""
    today = datetime.utcnow().date()
    week_ago = today - timedelta(days=7)
    
    # Get today's usage
    today_usage = EnergyUsage.query.join(Device).filter(
        Device.user_id == current_user.id,
        db.func.date(EnergyUsage.timestamp) == today
    ).all()
    
    # Get weekly usage
    weekly_usage = EnergyUsage.query.join(Device).filter(
        Device.user_id == current_user.id,
        EnergyUsage.timestamp >= week_ago
    ).all()
    
    today_total = sum(usage.watt_hours for usage in today_usage)
    week_total = sum(usage.watt_hours for usage in weekly_usage)
    
    return jsonify({
        'success': True,
        'today': {
            'watt_hours': today_total,
            'cost': today_total * 0.00012
        },
        'week': {
            'watt_hours': week_total,
            'cost': week_total * 0.00012
        },
        'usage_by_device': [
            {
                'device_id': usage.device_id,
                'device_name': usage.device.name,
                'watt_hours': usage.watt_hours,
                'timestamp': usage.timestamp.isoformat()
            }
            for usage in today_usage
        ]
    })

# ----------------- AUTHENTICATION ROUTES -----------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        data = request.json
        user = User.query.filter_by(username=data['username']).first()
        
        if user and user.check_password(data['password']):
            login_user(user)
            return jsonify({
                'success': True,
                'message': 'Logged in successfully',
                'user': user.to_dict()
            })
        
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    """User registration"""
    try:
        data = request.json
        
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'success': False, 'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        user = User(
            username=data['username'],
            email=data['email']
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': user.to_dict()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """User logout"""
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out'})

# ----------------- WEBSOCKET EVENTS -----------------

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Smart Home Server'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('device_status_request')
def handle_device_status(data):
    """Handle device status requests"""
    device_id = data.get('device_id')
    if device_id:
        device = Device.query.get(device_id)
        if device and (device.user_id == current_user.id or current_user.is_admin):
            emit('device_status_response', {
                'device_id': device_id,
                'status': device.status,
                'settings': device.settings_dict
            })

# ----------------- SYSTEM HEALTH -----------------

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'connected',
        'devices_count': Device.query.count(),
        'users_count': User.query.count()
    })

@app.route('/api/system/stats', methods=['GET'])
@login_required
def system_stats():
    """Get system statistics"""
    total_devices = Device.query.count()
    total_users = User.query.count()
    active_devices = Device.query.filter_by(status=True).count()
    
    return jsonify({
        'success': True,
        'stats': {
            'total_devices': total_devices,
            'total_users': total_users,
            'active_devices': active_devices,
            'uptime': get_system_uptime()
        }
    })

def get_system_uptime():
    """Get system uptime (simulated)"""
    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])
        return str(timedelta(seconds=uptime_seconds))
    return "Unknown"

# ----------------- INITIALIZATION -----------------

@app.before_first_request
def initialize():
    """Initialize the application"""
    try:
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@smartapp.com',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            logger.info("Admin user created")
        
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")

# ----------------- ERROR HANDLERS -----------------

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'success': False, 'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

# ----------------- MAIN -----------------

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Run the application
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True
    )
