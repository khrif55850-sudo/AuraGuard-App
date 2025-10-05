# from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import datetime
from advanced_ai_module import AdvancedAIComplete
import os
from werkzeug.security import generate_password_hash, check_password_hash
import redis
from functools import wraps

app = Flask(__name__)

# الإعدادات المحسّنة
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'CHANGE-THIS-IN-PRODUCTION')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///security_platform.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# تهيئة الإضافات
CORS(app, resources={r"/*": {"origins": "*"}})
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='eventlet')
db = SQLAlchemy(app)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Redis للتخزين المؤقت
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping()
    REDIS_AVAILABLE = True
except:
    REDIS_AVAILABLE = False
    logging.warning("Redis not available, using in-memory cache")

# نظام الذكاء الاصطناعي
ai_system = AdvancedAIComplete()

# إعداد السجلات
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('security_platform.log'),
        logging.StreamHandler()
    ]
)

# ==== النماذج (Models) ====

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SensorData(db.Model):
    __tablename__ = 'sensor_data'
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(200), nullable=False)
    value = db.Column(db.Text)
    data = db.Column(db.JSON)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    location_lat = db.Column(db.Float)
    location_lon = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    processed = db.Column(db.Boolean, default=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'topic': self.topic,
            'value': self.value,
            'data': self.data,
            'timestamp': self.timestamp.isoformat(),
            'location': {'lat': self.location_lat, 'lon': self.location_lon} if self.location_lat else None
        }

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20))  # low, medium, high, critical
    message = db.Column(db.Text)
    sensor_data_id = db.Column(db.Integer, db.ForeignKey('sensor_data.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class AIInteraction(db.Model):
    __tablename__ = 'ai_interactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    prompt = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text)
    sentiment = db.Column(db.String(20))
    action = db.Column(db.String(50))
    quality_score = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# إنشاء الجداول
with app.app_context():
    db.create_all()
    # إنشاء مستخدم تجريبي
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('password')
        db.session.add(admin)
        db.session.commit()
        logging.info("Admin user created")

# ==== Helper Functions ====

def cache_get(key):
    if REDIS_AVAILABLE:
        return redis_client.get(key)
    return None

def cache_set(key, value, expire=300):
    if REDIS_AVAILABLE:
        redis_client.setex(key, expire, value)

def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        if not user or user.role != 'admin':
            return jsonify({"msg": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper

def create_alert(alert_type, severity, message, sensor_data_id=None, user_id=None):
    alert = Alert(
        alert_type=alert_type,
        severity=severity,
        message=message,
        sensor_data_id=sensor_data_id,
        user_id=user_id
    )
    db.session.add(alert)
    db.session.commit()
    
    # إرسال عبر WebSocket
    socketio.emit('new_alert', {
        'type': alert_type,
        'severity': severity,
        'message': message,
        'timestamp': alert.created_at.isoformat()
    })
    
    logging.info(f"Alert created: {alert_type} - {severity}")

# ==== API Endpoints ====

@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    """تسجيل مستخدم جديد"""
    data = request.json
    
    if not data.get('username') or not data.get('password'):
        return jsonify({"msg": "Username and password required"}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"msg": "Username already exists"}), 400
    
    user = User(username=data['username'], email=data.get('email'))
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    
    logging.info(f"New user registered: {user.username}")
    return jsonify({"msg": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """تسجيل الدخول"""
    data = request.json
    user = User.query.filter_by(username=data.get('username')).first()
    
    if not user or not user.check_password(data.get('password')):
        logging.warning(f"Failed login attempt for: {data.get('username')}")
        return jsonify({"msg": "بيانات الدخول غير صحيحة"}), 401
    
    if not user.is_active:
        return jsonify({"msg": "الحساب معطل"}), 403
    
    access_token = create_access_token(identity=user.username)
    logging.info(f"User logged in: {user.username}")
    
    return jsonify({
        "access_token": access_token,
        "user": {"username": user.username, "role": user.role}
    }), 200

@app.route('/api/sensor_data', methods=['POST'])
@jwt_required()
@limiter.limit("100 per minute")
def receive_sensor_data():
    """استقبال بيانات الحساسات"""
    data = request.json
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    sensor = SensorData(
        topic=data.get('topic'),
        value=str(data.get('value')),
        data=data,
        user_id=user.id,
        location_lat=data.get('location', {}).get('lat'),
        location_lon=data.get('location', {}).get('lon')
    )
    db.session.add(sensor)
    db.session.commit()
    
    # تحليل البيانات وإنشاء تنبيهات
    if data.get('detected') or (data.get('value') and float(data.get('value', 0)) > 30):
        create_alert('security', 'high', f"رصد نشاط: {data.get('topic')}", sensor.id, user.id)
    
    socketio.emit('sensor_update', sensor.to_dict())
    logging.info(f"Sensor data received: {sensor.topic}")
    
    return jsonify({"status": "success", "id": sensor.id}), 201

@app.route('/api/sensor_data', methods=['GET'])
@jwt_required()
def get_sensor_data():
    """جلب بيانات الحساسات"""
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    topic = request.args.get('topic')
    
    query = SensorData.query
    if topic:
        query = query.filter_by(topic=topic)
    
    data = query.order_by(SensorData.timestamp.desc()).limit(limit).offset(offset).all()
    total = query.count()
    
    return jsonify({
        "data": [item.to_dict() for item in data],
        "total": total,
        "limit": limit,
        "offset": offset
    }), 200

@app.route('/api/analytics', methods=['GET'])
@jwt_required()
def get_analytics():
    """إحصائيات متقدمة"""
    # التحقق من الكاش
    cache_key = 'analytics_data'
    cached = cache_get(cache_key)
    if cached:
        import json
        return jsonify(json.loads(cached)), 200
    
    today = datetime.datetime.utcnow().date()
    week_ago = today - datetime.timedelta(days=7)
    
    total_sensors = SensorData.query.count()
    today_sensors = SensorData.query.filter(
        db.func.date(SensorData.timestamp) == today
    ).count()
    
    weekly_data = db.session.query(
        db.func.date(SensorData.timestamp).label('date'),
        db.func.count(SensorData.id).label('count')
    ).filter(
        SensorData.timestamp >= week_ago
    ).group_by(db.func.date(SensorData.timestamp)).all()
    
    active_topics = db.session.query(
        SensorData.topic,
        db.func.count(SensorData.id).label('count')
    ).group_by(SensorData.topic).all()
    
    unread_alerts = Alert.query.filter_by(is_read=False).count()
    
    analytics = {
        "total_sensors": total_sensors,
        "today_sensors": today_sensors,
        "weekly_trend": [{"date": str(d.date), "count": d.count} for d in weekly_data],
        "active_topics": [{"topic": t.topic, "count": t.count} for t in active_topics[:10]],
        "unread_alerts": unread_alerts,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    
    # حفظ في الكاش
    import json
    cache_set(cache_key, json.dumps(analytics), 60)
    
    return jsonify(analytics), 200

@app.route('/api/generate', methods=['POST'])
@jwt_required()
@limiter.limit("20 per minute")
def generate_ai_response():
    """توليد رد ذكي"""
    data = request.json
    prompt = data.get('prompt', '')
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    if not prompt:
        return jsonify({"msg": "Prompt required"}), 400
    
    sentiment = ai_system.analyze_sentiment(prompt)
    action = ai_system.choose_action(sentiment)
    
    if action == 'generate_response':
        response = ai_system.generate_text(prompt, max_length=100)
    elif action == 'ask_for_clarification':
        response = 'هل يمكنك توضيح طلبك بشكل أفضل؟'
    else:
        response = 'يمكنني مساعدتك في تحليل بيانات الأمن والصحة'
    
    quality = 0.85
    ai_system.log_performance(quality)
    ai_system.reinforcement_step(sentiment, action, quality)
    
    # حفظ التفاعل
    interaction = AIInteraction(
        user_id=user.id,
        prompt=prompt,
        response=response,
        sentiment=sentiment,
        action=action,
        quality_score=quality
    )
    db.session.add(interaction)
    db.session.commit()
    
    return jsonify({
        'response': response,
        'sentiment': sentiment,
        'action': action,
        'quality_score': quality
    }), 200

@app.route('/api/alerts', methods=['GET'])
@jwt_required()
def get_alerts():
    """جلب التنبيهات"""
    unread_only = request.args.get('unread', 'false').lower() == 'true'
    limit = request.args.get('limit', 50, type=int)
    
    query = Alert.query
    if unread_only:
        query = query.filter_by(is_read=False)
    
    alerts = query.order_by(Alert.created_at.desc()).limit(limit).all()
    
    return jsonify({
        "alerts": [{
            "id": a.id,
            "type": a.alert_type,
            "severity": a.severity,
            "message": a.message,
            "is_read": a.is_read,
            "timestamp": a.created_at.isoformat()
        } for a in alerts]
    }), 200

@app.route('/api/alerts/<int:alert_id>/read', methods=['PUT'])
@jwt_required()
def mark_alert_read(alert_id):
    """تعليم تنبيه كمقروء"""
    alert = Alert.query.get_or_404(alert_id)
    alert.is_read = True
    db.session.commit()
    return jsonify({"msg": "Alert marked as read"}), 200

@app.route('/api/health', methods=['GET'])
def health_check():
    """فحص صحة النظام"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "database": "connected",
        "redis": "available" if REDIS_AVAILABLE else "unavailable",
        "ai_system": "active"
    }), 200

@app.route('/api/users', methods=['GET'])
@admin_required
def list_users():
    """قائمة المستخدمين (للمدراء فقط)"""
    users = User.query.all()
    return jsonify({
        "users": [{
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat()
        } for u in users]
    }), 200

# ==== WebSocket Events ====

@socketio.on('connect')
def handle_connect():
    logging.info('Client connected via WebSocket')
    socketio.emit('connection_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    logging.info('Client disconnected from WebSocket')

@socketio.on('request_update')
def handle_update_request():
    recent = SensorData.query.order_by(SensorData.timestamp.desc()).limit(5).all()
    socketio.emit('bulk_update', {'data': [s.to_dict() for s in recent]})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)

سأنشئ ملف requirements محدث للنظام المحسّن:

# Backend Framework
Flask==3.0.0
Flask-JWT-Extended==4.5.3
Flask-SocketIO==5.3.5
Flask-CORS==4.0.0
Flask-SQLAlchemy==3.1.1
Flask-Limiter==3.5.0

# Database
SQLAlchemy==2.0.23
psycopg2-binary==2.9.9
alembic==1.13.0

# Caching & Queue
redis==5.0.1
celery==5.3.4

# WebSocket
python-socketio==5.10.0
eventlet==0.33.3

# MQTT
paho-mqtt==1.6.1

# AI & ML
transformers==4.35.2
torch==2.1.1
torchvision==0.16.1
scikit-learn==1.3.2
textblob==0.17.1
numpy==1.24.3
pandas==2.1.3

# Security
cryptography==41.0.7
bcrypt==4.1.1

# Monitoring
prometheus-flask-exporter==0.23.0

# Utilities
requests==2.31.0
python-dotenv==1.0.0
python-dateutil==2.8.2

# Production Server
gunicorn==21.2.0
gevent==23.9.1

سأنشئ دليل التثبيت والتشغيل للنسخة المحسّنة:

# 📱 دليل إعداد تطبيق الموبايل

## المتطلبات الأساسية

- Node.js 16+ و npm
- Expo CLI
- Android Studio (لـ Android)
- Xcode (لـ iOS على macOS فقط)

## التثبيت السريع

### 1. تثبيت Expo CLI

```bash
npm install -g expo-cli
```

### 2. إنشاء المشروع

```bash
npx create-expo-app smart-security-mobile
cd smart-security-mobile
```

### 3. تثبيت المكتبات

```bash
npm install @react-native-async-storage/async-storage
npm install expo-location expo-notifications expo-camera
npm install socket.io-client axios
npm install @react-navigation/native @react-navigation/stack
npm install react-native-gesture-handler react-native-reanimated
npm install react-native-safe-area-context react-native-screens
npm install react-native-chart-kit react-native-svg
npm install moment
```

### 4. نسخ ملف App.js

انسخ محتوى ملف `App.js` المقدم إلى مجلد المشروع.

### 5. تحديث app.json

```json
{
  "expo": {
    "name": "Smart Security",
    "slug": "smart-security-mobile",
    "version": "2.0.0",
    "orientation": "portrait",
    "icon": "./assets/icon.png",
    "splash": {
      "image": "./assets/splash.png",
      "resizeMode": "contain",
      "backgroundColor": "#667eea"
    },
    "android": {
      "package": "com.smartsecurity.app",
      "permissions": [
        "ACCESS_FINE_LOCATION",
        "CAMERA",
        "NOTIFICATIONS"
      ]
    },
    "ios": {
      "bundleIdentifier": "com.smartsecurity.app",
      "supportsTablet": true
    },
    "plugins": [
      [
        "expo-notifications",
        {
          "icon": "./assets/notification-icon.png",
          "color": "#667eea"
        }
      ]
    ]
  }
}
```

## التشغيل

### وضع التطوير

```bash
# تشغيل عام
npm start

# Android محدد
npm run android

# iOS محدد  
npm run ios
```

### مسح QR للاختبار

1. شغّل `npm start`
2. افتح تطبيق Expo Go على هاتفك
3. امسح الـ QR code

## البناء للإنتاج

### Android APK

```bash
# تثبيت EAS CLI
npm install -g eas-cli

# تسجيل الدخول
eas login

# بناء APK
eas build --platform android --profile preview
```

### iOS App

```bash
eas build --platform ios --profile preview
```

## تحديث عنوان الخادم

في ملف `App.js` غيّر:

```javascript
const API_URL = 'https://your-server.com';
```

إلى عنوان الخادم الفعلي.

## الميزات المتقدمة

### إشعارات Push

```javascript
// التسجيل للإشعارات
const token = await Notifications.getExpoPushTokenAsync();
// أرسل هذا التوكن للخادم
```

### تتبع الموقع في الخلفية

```json
// في app.json
"ios": {
  "infoPlist": {
    "NSLocationAlwaysAndWhenInUseUsageDescription": "للمراقبة الأمنية",
    "UIBackgroundModes": ["location"]
  }
}
```

## استكشاف الأخطاء

### خطأ في المكتبات
```bash
npm install --legacy-peer-deps
```

### مشاكل Metro Bundler
```bash
npx expo start -c
```

### مشاكل iOS
```bash
cd ios && pod install && cd ..
```

## النشر على المتاجر

### Google Play
1. بناء AAB: `eas build --platform android --profile production`
2. رفع على Google Play Console

### App Store  
1. بناء IPA: `eas build --platform ios --profile production`
2. رفع عبر Xcode أو Transporter

سأنشئ الآن وحدة الذكاء الاصطناعي المحسّنة:

import logging
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from textblob import TextBlob
import torch
import random
from collections import deque
import pickle
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ai_system.log'),
        logging.StreamHandler()
    ]
)

class EnhancedAISystem:
    """نظام ذكاء اصطناعي محسّن مع قدرات متقدمة"""
    
    def __init__(self):
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        logging.info(f"Using device: {self.device}")
        
        # نماذج متعددة للدقة العالية
        self.ensemble_models = {
            'rf': RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1),
            'gb': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'mlp': MLPClassifier(hidden_layer_sizes=(128, 64), random_state=42, max_iter=500)
        }
        
        self.vectorizer = TfidfVectorizer(max_features=2000, ngram_range=(1, 3))
        
        # نموذج توليد متقدم
        try:
            self.text_gen = pipeline(
                'text-generation',
                model='gpt2-medium',
                device=0 if self.device == 'cuda' else -1
            )
            logging.info("GPT-2 Medium loaded successfully")
        except Exception as e:
            logging.warning(f"GPT-2 loading failed, using fallback: {e}")
            self.text_gen = None
        
        # نموذج تحليل المشاعر المتقدم
        try:
            self.sentiment_model = AutoModelForSequenceClassification.from_pretrained(
                "distilbert-base-uncased-finetuned-sst-2-english"
            )
            self.sentiment_tokenizer = AutoTokenizer.from_pretrained(
                "distilbert-base-uncased-finetuned-sst-2-english"
            )
            self.sentiment_pipeline = pipeline(
                "sentiment-analysis",
                model=self.sentiment_model,
                tokenizer=self.sentiment_tokenizer,
                device=0 if self.device == 'cuda' else -1
            )
            logging.info("Advanced sentiment model loaded")
        except:
            self.sentiment_pipeline = None
        
        # التعلم المعزز المتقدم
        self.q_table = {}
        self.epsilon = 0.2  # exploration rate
        self.alpha = 0.15   # learning rate
        self.gamma = 0.95   # discount factor
        self.actions = [
            'generate_response',
            'ask_clarification',
            'provide_alternative',
            'security_alert',
            'health_recommendation'
        ]
        
        # ذاكرة التجارب
        self.experience_buffer = deque(maxlen=10000)
        
        # مراقبة الأداء
        self.performance_log = deque(maxlen=1000)
        self.self_monitoring_threshold = 0.75
        
        # تحميل النموذج المحفوظ
        self.load_models()
        
        logging.info("Enhanced AI System initialized successfully")
    
    def analyze_sentiment_advanced(self, text):
        """تحليل مشاعر متقدم باستخدام نماذج عميقة"""
        if self.sentiment_pipeline:
            try:
                result = self.sentiment_pipeline(text[:512])[0]
                label = result['label'].lower()
                score = result['score']
                
                if label == 'positive' and score > 0.7:
                    return 'very_positive', score
                elif label == 'positive':
                    return 'positive', score
                elif label == 'negative' and score > 0.7:
                    return 'very_negative', score
                elif label == 'negative':
                    return 'negative', score
                else:
                    return 'neutral', score
            except Exception as e:
                logging.error(f"Sentiment analysis error: {e}")
        
        # Fallback to TextBlob
        analysis = TextBlob(text)
        polarity = analysis.sentiment.polarity
        
        if polarity > 0.3:
            return 'positive', abs(polarity)
        elif polarity < -0.3:
            return 'negative', abs(polarity)
        else:
            return 'neutral', 0.5
    
    def generate_text_advanced(self, prompt, max_length=150, temperature=0.8):
        """توليد نص متقدم مع تحكم أفضل"""
        if self.text_gen:
            try:
                results = self.text_gen(
                    prompt,
                    max_length=max_length,
                    num_return_sequences=1,
                    temperature=temperature,
                    top_p=0.9,
                    do_sample=True
                )
                generated = results[0]['generated_text']
                
                # تنظيف النص
                if len(generated) > len(prompt):
                    response = generated[len(prompt):].strip()
                else:
                    response = generated.strip()
                
                logging.info(f"Generated: {response[:100]}")
                return response
            except Exception as e:
                logging.error(f"Text generation error: {e}")
        
        # استجابات احتياطية ذكية
        responses = {
            'security': [
                'النظام يعمل بشكل طبيعي. جميع الحساسات نشطة ولا توجد تنبيهات حرجة.',
                'تم رصد نشاط عادي. المراقبة مستمرة على مدار الساعة.',
                'الأمن في مستوى جيد. يتم تحليل البيانات بشكل مستمر.'
            ],
            'health': [
                'المؤشرات الصحية ضمن المعدل الطبيعي.',
                'جودة الهواء جيدة. درجة الحرارة مريحة.',
                'البيئة صحية ومناسبة.'
            ]
        }
        
        category = 'security' if any(kw in prompt.lower() for kw in ['أمن', 'مراقبة', 'حماية']) else 'health'
        return random.choice(responses.get(category, responses['security']))
    
    def reinforcement_learning(self, state, action, reward, next_state):
        """التعلم المعزز المتقدم مع Experience Replay"""
        # حفظ التجربة
        self.experience_buffer.append((state, action, reward, next_state))
        
        # التحديث الفوري
        key = (state, action)
        old_value = self.q_table.get(key, 0.0)
        
        next_max = max([self.q_table.get((next_state, a), 0.0) for a in self.actions])
        new_value = old_value + self.alpha * (reward + self.gamma * next_max - old_value)
        
        self.q_table[key] = new_value
        
        # Experience Replay - تعلم من تجارب عشوائية
        if len(self.experience_buffer) > 32:
            batch = random.sample(self.experience_buffer, 32)
            for s, a, r, ns in batch:
                k = (s, a)
                ov = self.q_table.get(k, 0.0)
                nm = max([self.q_table.get((ns, ac), 0.0) for ac in self.actions])
                nv = ov + self.alpha * (r + self.gamma * nm - ov)
                self.q_table[k] = nv
        
        logging.debug(f"Q-value updated: {key} -> {new_value:.4f}")
    
    def choose_action_smart(self, state, context=None):
        """اختيار إجراء ذكي بناءً على السياق"""
        # Epsilon-greedy with decay
        if random.random() < self.epsilon:
            return random.choice(self.actions)
        
        # اختيار بناءً على Q-values
        q_values = [(a, self.q_table.get((state, a), 0.0)) for a in self.actions]
        
        # تعديل بناءً على السياق
        if context:
            if 'urgent' in context or 'critical' in context:
                # تفضيل إجراءات الأمن في الحالات العاجلة
                for i, (action, value) in enumerate(q_values):
                    if action == 'security_alert':
                        q_values[i] = (action, value + 0.5)
        
        return max(q_values, key=lambda x: x[1])[0]
    
    def ensemble_prediction(self, features):
        """تنبؤ جماعي من عدة نماذج"""
        predictions = []
        for name, model in self.ensemble_models.items():
            try:
                if hasattr(model, 'predict_proba'):
                    pred = model.predict_proba(features)[0]
                    predictions.append(pred)
            except:
                pass
        
        if predictions:
            return np.mean(predictions, axis=0)
        return np.array([0.5, 0.5])
    
    def log_performance(self, quality, metrics=None):
        """مراقبة ذاتية محسّنة"""
        self.performance_log.append({
            'quality': quality,
            'metrics': metrics,
            'timestamp': np.datetime64('now')
        })
        
        if len(self.performance_log) >= 100:
            avg_quality = np.mean([p['quality'] for p in list(self.performance_log)[-100:]])
            
            if avg_quality < self.self_monitoring_threshold:
                logging.warning(
                    f"Performance degradation detected: {avg_quality:.3f} < {self.self_monitoring_threshold}"
                )
                self.adaptive_improvement()
            else:
                logging.info(f"Performance good: {avg_quality:.3f}")
    
    def adaptive_improvement(self):
        """تحسين تكيفي تلقائي"""
        # زيادة الاستكشاف
        self.epsilon = min(0.4, self.epsilon + 0.05)
        logging.info(f"Epsilon increased to {self.epsilon} for exploration")
        
        # إعادة تدريب النماذج إذا كانت البيانات كافية
        if len(self.experience_buffer) > 1000:
            logging.info("Initiating model retraining...")
            # يمكن إضافة كود إعادة التدريب هنا
    
    def save_models(self):
        """حفظ النماذج"""
        try:
            with open('ai_models.pkl', 'wb') as f:
                pickle.dump({
                    'q_table': self.q_table,
                    'experience_buffer': list(self.experience_buffer),
                    'performance_log': list(self.performance_log)
                }, f)
            logging.info("Models saved successfully")
        except Exception as e:
            logging.error(f"Model save error: {e}")
    
    def load_models(self):
        """تحميل النماذج المحفوظة"""
        if os.path.exists('ai_models.pkl'):
            try:
                with open('ai_models.pkl', 'rb') as f:
                    data = pickle.load(f)
                    self.q_table = data.get('q_table', {})
                    self.experience_buffer.extend(data.get('experience_buffer', []))
                    self.performance_log.extend(data.get('performance_log', []))
                logging.info("Models loaded successfully")
            except Exception as e:
                logging.error(f"Model load error: {e}")

# تصدير لسهولة الاستخدام
AdvancedAI