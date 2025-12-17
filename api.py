from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import joblib
import pandas as pd
import numpy as np
import os
from datetime import datetime
import uuid

app = Flask(__name__)

# DATABASE_URL = os.environ.get('DATABASE_URL') 
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:wrdnsIhAOSYQZGRXmcvimPnGBTJcZyyO@shinkansen.proxy.rlwy.net:30618/railway')
if not DATABASE_URL:
    print("FATAL: DATABASE_URL environment variable is not set.")
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)

class ApiToken(db.Model):
    __tablename__ = 'api_tokens'
    token = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='tokens') 

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(120))
    
    predictions = db.relationship('PredictionHistory', backref='user', lazy=True)

class PredictionHistory(db.Model):
    __tablename__ = 'prediction_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    input_data = db.Column(db.JSON, nullable=False)
    predicted_charges = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def token_required(f):
    def decorated(*args, **kwargs):
        try:
            token = request.headers.get('Authorization')
            if not token or not token.startswith('Bearer '):
                return jsonify({'status': 'error', 'message': 'Token otentikasi hilang atau format salah!'}), 401
            
            token_value = token.split(" ")[1]
            api_token = ApiToken.query.filter_by(token=token_value).first()
            
            if not api_token:
                return jsonify({'status': 'error', 'message': 'Token tidak valid atau kadaluarsa!'}), 401
            
            kwargs['current_user'] = api_token.user
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Error otentikasi: {str(e)}'}), 401
    decorated.__name__ = f.__name__
    return decorated


@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Data JSON tidak valid!'}), 400
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not all([username, email, password]):
            return jsonify({'status': 'error', 'message': 'Semua bidang wajib diisi!'}), 400

        if len(username) < 3:
            return jsonify({'status': 'error', 'message': 'Username minimal 3 karakter!'}), 400
        if len(password) < 6:
            return jsonify({'status': 'error', 'message': 'Password minimal 6 karakter!'}), 400
        
        if '@' not in email or '.' not in email:
            return jsonify({'status': 'error', 'message': 'Format email tidak valid!'}), 400

        if User.query.filter((User.username == username) | (User.email == email)).first():
            return jsonify({'status': 'error', 'message': 'Username atau Email sudah terdaftar!'}), 409

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password_hash=hashed_password, full_name=data.get('full_name', username))

        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Pendaftaran berhasil!', 
            'user_id': new_user.id,
            'username': new_user.username
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Terjadi kesalahan: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Data JSON tidak valid!'}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not all([username, password]):
            return jsonify({'status': 'error', 'message': 'Username dan password wajib diisi!'}), 400

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            ApiToken.query.filter_by(user_id=user.id).delete()
            new_token = ApiToken(user_id=user.id)
            db.session.add(new_token)
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': 'Login berhasil!',
                'token': new_token.token,
                'user_id': user.id,
                'username': user.username
            }), 200
        
        return jsonify({'status': 'error', 'message': 'Username atau Password salah!'}), 401
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Terjadi kesalahan: {str(e)}'}), 500

@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    try:
        return jsonify({
            'status': 'success',
            'data': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'full_name': current_user.full_name
            },
            'message': 'Profil berhasil diambil!'
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Terjadi kesalahan: {str(e)}'}), 500

@app.route('/api/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Data JSON tidak valid!'}), 400
        
        if 'full_name' in data:
            current_user.full_name = data.get('full_name', current_user.full_name)

        if 'email' in data:
            new_email = data.get('email')
            if new_email != current_user.email:
                existing_user = User.query.filter_by(email=new_email).first()
                if existing_user:
                    return jsonify({'status': 'error', 'message': 'Email sudah digunakan!'}), 409
                current_user.email = new_email
        
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Profil berhasil diperbarui!',
            'data': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'full_name': current_user.full_name
            }
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Terjadi kesalahan: {str(e)}'}), 500

LOWER_BOUND_BMI = 21.234750000000002
UPPER_BOUND_BMI = 40.61724999999999
FEATURE_COLS = ['age', 'children', 'bmi_clean', 'sex_male', 'smoker_yes', 'region_northwest', 'region_southeast', 'region_southwest']

MODEL_PATH = 'insurance_model.pkl'
try:
    model = joblib.load(MODEL_PATH)
    print("Model ML berhasil dimuat.")
except Exception as e:
    print(f"Error memuat model: {e}")
    model = None


@app.route('/api/predict', methods=['POST'])
@token_required
def predict(current_user):
    if model is None:
        return jsonify({"status": "error", "message": "Model tidak tersedia."}), 500

    try:
        data = request.get_json(force=True)
    except:
        return jsonify({"status": "error", "message": "Permintaan harus berupa JSON."}), 400

    required_keys = ['age', 'bmi', 'children', 'sex', 'smoker', 'region']
    if not all(key in data for key in required_keys):
         return jsonify({"status": "error", "message": "Input tidak lengkap. Diperlukan: age, bmi, children, sex, smoker, region"}), 400
    
    try:
        age = int(data.get('age'))
        bmi = float(data.get('bmi'))
        children = int(data.get('children'))
        sex = str(data.get('sex')).lower()
        smoker = str(data.get('smoker')).lower()
        region = str(data.get('region')).lower()
        
        if not (0 <= age <= 120):
            return jsonify({"status": "error", "message": "Umur harus antara 0-120 tahun."}), 400
        if not (10 <= bmi <= 60):
            return jsonify({"status": "error", "message": "BMI harus antara 10-60."}), 400
        if not (0 <= children <= 20):
            return jsonify({"status": "error", "message": "Jumlah anak harus antara 0-20."}), 400
        if sex not in ['male', 'female']:
            return jsonify({"status": "error", "message": "Sex harus 'male' atau 'female'."}), 400
        if smoker not in ['yes', 'no']:
            return jsonify({"status": "error", "message": "Smoker harus 'yes' atau 'no'."}), 400
        if region not in ['northeast', 'northwest', 'southeast', 'southwest']:
            return jsonify({"status": "error", "message": "Region tidak valid. Pilihan: northeast, northwest, southeast, southwest"}), 400

        data_input = pd.DataFrame([{
            'age': age,
            'bmi': bmi,
            'children': children,
            'sex': sex,
            'smoker': smoker,
            'region': region
        }])
        
        data_input['bmi_clean'] = np.clip(data_input['bmi'], LOWER_BOUND_BMI, UPPER_BOUND_BMI)
        data_input = data_input.drop('bmi', axis=1)
        data_input_encoded = pd.get_dummies(data_input, columns=['sex', 'smoker', 'region'], drop_first=True)
        
        final_input = pd.DataFrame(0, index=[0], columns=FEATURE_COLS)
        for col in data_input_encoded.columns:
            if col in FEATURE_COLS:
                final_input[col] = data_input_encoded[col]

        original_input = {
            'age': age,
            'bmi': bmi,
            'children': children,
            'sex': sex,
            'smoker': smoker,
            'region': region
        }

        # Prediksi
        prediction_log = model.predict(final_input)
        prediction = np.expm1(prediction_log)[0]
        
        new_history = PredictionHistory(
            user_id=current_user.id,
            input_data=original_input,
            predicted_charges=float(prediction)
        )
        db.session.add(new_history)
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "message": "Prediksi berhasil!",
            "predicted_charges": float(prediction),
            "predicted_charges_formatted": f"${prediction:,.2f}",
            "history_id": new_history.id,
            "input_summary": {
                "age": age,
                "bmi": bmi,
                "children": children,
                "sex": sex,
                "smoker": smoker,
                "region": region
            }
        }), 200
    
    except ValueError as ve:
        return jsonify({"status": "error", "message": f"Format data tidak valid: {str(ve)}"}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Terjadi kesalahan saat prediksi: {str(e)}"}), 500

@app.route('/api/history', methods=['GET'])
@token_required
def get_history(current_user):
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        if per_page > 100:
            per_page = 100
        
        history_records = PredictionHistory.query.filter_by(user_id=current_user.id).order_by(PredictionHistory.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        
        output = []
        for record in history_records.items:
            output.append({
                'id': record.id,
                'input': record.input_data,
                'charges': f"${record.predicted_charges:,.2f}",
                'predicted_charges_raw': record.predicted_charges,
                'date': record.created_at.isoformat(),
            })
        
        return jsonify({
            'status': 'success',
            'message': 'Riwayat prediksi berhasil diambil!',
            'data': output,
            'pagination': {
                'total': history_records.total,
                'page': history_records.page,
                'per_page': history_records.per_page,
                'total_pages': history_records.pages
            }
        }), 200
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Terjadi kesalahan: {str(e)}'}), 500

def global_stats_default_empty():
    return {
        "total_global_predictions": 0,
        "smoker_distribution": {},
        "sex_distribution": {},
        "top_region": "N/A",
        "average_charges_global": "$0",
        "avg_charges_by_smoker": {},
        "avg_charges_by_age_group": [],
        "scatter_plot_data": []
    }

def calculate_global_stats():
    try:
        all_history = PredictionHistory.query.all()
        
        smokers = []
        sexes = []
        regions = []
        charges = []
        ages = []  
        correlation_data = []

        for record in all_history:
            input_data = record.input_data 
            if input_data and record.predicted_charges is not None:
                smokers.append(input_data.get('smoker'))
                sexes.append(input_data.get('sex'))
                regions.append(input_data.get('region'))
                charges.append(record.predicted_charges)
                ages.append(input_data.get('age'))    

                # scatter plot (Age vs Charges vs Smoker)
                correlation_data.append({
                    'age': input_data.get('age'),
                    'charges': record.predicted_charges,
                    'smoker': input_data.get('smoker')
                })

        if not charges:
            return global_stats_default_empty()
        
        df_stats = pd.DataFrame({
            'smoker': smokers, 
            'sex': sexes, 
            'region': regions, 
            'charges': charges, 
            'age': ages
        })

        smoker_counts = df_stats['smoker'].value_counts(normalize=True).mul(100).to_dict()
        sex_counts = df_stats['sex'].value_counts(normalize=True).mul(100).to_dict()
        top_region = df_stats['region'].mode().iloc[0] if len(df_stats['region'].mode()) > 0 else "N/A"
        avg_charges_global = db.session.query(db.func.avg(PredictionHistory.predicted_charges)).scalar()
        
        # Rata-Rata Charges berdasarkan Smoker (Untuk Bar Chart)
        avg_charges_by_smoker = df_stats.groupby('smoker')['charges'].mean().to_dict()

        # Rata-Rata Charges berdasarkan Kelompok Usia (Untuk Bar/Line Chart)
        bins = [18, 25, 40, 55, 100]
        labels = ['18-25', '26-40', '41-55', '56+']
        df_stats['age_group'] = pd.cut(df_stats['age'], bins=bins, labels=labels, right=False)

        avg_charges_by_age = df_stats.groupby('age_group', observed=True)['charges'].mean().reset_index()
        age_group_data = avg_charges_by_age.rename(columns={'age_group': 'group', 'charges': 'average_charge'}).to_dict('records')
        
        
        global_stats = {
            "total_global_predictions": len(all_history),
            "smoker_distribution": {k: f"{v:.1f}%" for k, v in smoker_counts.items()},
            "sex_distribution": {k: f"{v:.1f}%" for k, v in sex_counts.items()},
            "top_region": top_region,
            "average_charges_global": f"${avg_charges_global:,.0f}" if avg_charges_global else "$0",
            
            "avg_charges_by_smoker": avg_charges_by_smoker,
            "avg_charges_by_age_group": age_group_data,
            "scatter_plot_data": correlation_data[:500] 
        }
        
        return global_stats
    
    except Exception as e:
        print(f"Error calculating global stats: {str(e)}")
        return global_stats_default_empty()

@app.route('/api/dashboard', methods=['GET'])
@token_required
def get_full_dashboard(current_user):
    try:
        total_predictions = PredictionHistory.query.filter_by(user_id=current_user.id).count()

        latest_activities = PredictionHistory.query.filter_by(user_id=current_user.id).order_by(PredictionHistory.created_at.desc()).limit(5).all()
        
        activities_list = []
        for activity in latest_activities:
            activities_list.append({
                'id': activity.id,
                'charges': f"${activity.predicted_charges:,.0f}",
                'age': activity.input_data.get('age') if activity.input_data else 'N/A',
                'bmi': activity.input_data.get('bmi') if activity.input_data else 'N/A',
                'smoker': activity.input_data.get('smoker') if activity.input_data else 'N/A',
                'date': activity.created_at.strftime("%d %b %Y, %H:%M")
            })

        avg_charges = db.session.query(db.func.avg(PredictionHistory.predicted_charges)).filter_by(user_id=current_user.id).scalar()
        
        MODEL_R2 = 0.8800

        user_stats = {
            "full_name": current_user.full_name,
            "username": current_user.username,
            "total_predictions_user": total_predictions,
            "r2_score": f"{MODEL_R2:.2f}",
            "average_charges_user": f"${avg_charges:,.0f}" if avg_charges else "$0",
            "system_status": "Online",
            "last_updated": datetime.now().strftime("%d %b %Y, %H:%M"),
            "latest_activities": activities_list
        }

        global_stats = calculate_global_stats()
        
        return jsonify({
            "status": "success",
            "message": "Dashboard berhasil dimuat!",
            "user_data": user_stats,
            "global_stats": global_stats
        }), 200
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Terjadi kesalahan: {str(e)}'}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))