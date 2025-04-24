import logging, psycopg2, hashlib, random, os, base64, numpy as np, hmac
logging.basicConfig(level=logging.INFO, format=' %(asctime)s -  %(levelname)s:  %(message)s')

from datetime import datetime, timedelta
from flask import request, Blueprint, redirect, current_app, jsonify
from flaskr.db import get_existing_db
from flaskr.ext.utils import get_field, load_model, get_vector, detect_faces
from flaskr.ext.fcs import FCS
from flask_jwt_extended import create_access_token
from psycopg2.extras import RealDictCursor
from werkzeug.utils import secure_filename

bp = Blueprint('auth', __name__, url_prefix='/auth')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def check_unique(db, table_name, field_name, field_value):
    db = get_existing_db()
    db_cursor = db.cursor(cursor_factory=RealDictCursor)

    db_cursor.execute(f"""
                SELECT id FROM {table_name} where {field_name}='{field_value}' LIMIT 1;
            """)
    res = db_cursor.fetchone()
    if res == None:
        return res
    
    return res

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@bp.route('/check-status', methods=['POST'], strict_slashes=False)
def check_status():
    if request.method == 'POST':
        res = get_field(req=request)
        request_received = datetime.now()
        bid_id = res.get('BID_identifier', None)
        
        try:
            db = get_existing_db()
            db_cursor = db.cursor(cursor_factory=RealDictCursor)
            uid = check_unique(db, table_name='users', field_name='bid_identifier', field_value=bid_id)
            if uid == None:
                return {
                    'status': 200,
                    'message': "Failed to find user.",
                    'error_details': f"User with BID {bid_id} not registered yet.",
                    'request_received': request_received,
                    'request_data': res
                }, 200
            else:
                uid = uid.get('id', None)
                db_cursor.execute(f"""
                    SELECT id from user_biometric where user_id={uid};
                """)
                if db_cursor.fetchone() == None:
                    return {
                        'status': 200,
                        'message': "User have not registered their biometric template.",
                        'error_details': f"User with BID {bid_id} has already been registered, but not the biometric template.",
                        'request_received': request_received,
                        'request_data': res
                    }, 200
                else:
                    return {
                        'status': 200,
                        'message': "User has already registered.",
                        'error_details': f"User with BID {bid_id} has already been completely registered",
                        'request_received': request_received,
                        'request_data': res
                    }, 200
        except TimeoutError as terror:
            return {
                'status': 408,
                'message': "Timeout error.",
                'error_details': terror,
                'request_received': request_received,
                'request_data': res
                    }, 408
        except Exception as error:
            return {
                'status': 500,
                'message': "Failed to register.",
                'error_details': error,
                'request_received': request_received,
                'request_data': res
                    }, 500

@bp.route('/register', methods=['POST'], strict_slashes=False)
def handle_register():
    if request.method == 'POST':
        res = get_field(req=request)
        request_received = datetime.now()

        nik = res.get('nik', None)
        full_name = res.get('full_name', None)
        BID_identifier = res.get('BID_identifier', str(random.randint(10000, 99999)))
        registered_at = request_received

        if None in (nik, full_name, BID_identifier, registered_at):
            return {
                'received_data': res,
                'status': 400,
                'message': "There is some field missing.",
                'error_details': f"(nik, full_name, BID_identifier)"
                    }, 400
        
        try:
            db = get_existing_db()
            db_cursor = db.cursor(cursor_factory=RealDictCursor)
            bid_check=check_unique(db, 'users', 'BID_identifier', BID_identifier)
            nik_check=check_unique(db, 'users', 'nik', nik)

            if bid_check == None and nik_check == None:
                db_cursor.execute("""
                    INSERT INTO users (nik, full_name, BID_identifier, registered_at)
                        VALUES (%s, %s, %s, %s)
                    """, (
                    nik, full_name, BID_identifier, registered_at
                    )
                )
                db.commit()
            else:
                return {
                    'status': 400,
                    'message': "Failed to register.",
                    'error_details': f"NIK {nik} or BID {BID_identifier} already exists.",
                    'request_received': request_received,
                    'request_data': res
                    }, 400
        except psycopg2.DatabaseError as error:
            logging.error(error)
            raise error
        except TimeoutError as terror:
            return {
                'status': 408,
                'message': "Timeout error.",
                'error_details': terror,
                'request_received': request_received,
                'request_data': res
                    }, 408
        except Exception as error:
            return {
                'status': 500,
                'message': "Failed to register.",
                'error_details': error,
                'request_received': request_received,
                'request_data': res
                    }, 500
        
        return {
            "message":f"User with NIK {nik} successfully registered",
            "status": 201,
            'request_received': request_received,
            'request_data': res
        }, 201
    
@bp.route('/register-biometric', methods=['POST'], strict_slashes=False)
def handle_register_biometric():
    if request.method == 'POST':
        request_received = datetime.now()
        res = get_field(req=request)
        nik = res.get('nik', None)
        file = request.files['file']
        db = get_existing_db()
        uid=check_unique(db, 'users', 'nik', nik)

        if uid == None:
            return {
                'received_data': res,
                'status': 400,
                'message': f"User id {uid} not exists.",
                'error_details': f"(nik, file upload)"
                }, 400
        if None in (nik, file):
            return {
                'received_data': res,
                'status': 400,
                'message': "There is some data missing.",
                'error_details': f"(nik, file upload)"
                    }, 400
        
        if file.filename == '':
            return {
                'received_data': {**res, 'filename': file.filename},
                'status': 400,
                'message': "There is some data missing.",
                'error_details': f"(nik, file upload)"
                    }, 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join('flaskr/public', filename))
        
        # Convert face image to embedding (biometric template)
        try:
            model = load_model('flaskr/public/vggface2.h5')
            db_cursor = db.cursor(cursor_factory=RealDictCursor)
            uid = uid.get('id', None)
            embedding_check=check_unique(db, 'user_biometric', 'user_id', uid)
            embedding = get_vector(image_dir=f'flaskr/public/{file.filename}', classifier=model, detect_faces=detect_faces).flatten()
            fcs = FCS(biometric_template=embedding, maximum_fix=96)
            commitment = fcs.get_commitment()
            helper_db = base64.b64encode(bytes(np.packbits(commitment.helper_data))).decode('utf-8')

            if embedding_check == None:
                db_cursor.execute("""
                    INSERT INTO user_biometric (user_id, embedding, created_at, last_updated)
                    VALUES (%s, %s, %s, %s)
                    """, (
                        uid, embedding.tolist(), request_received, request_received
                    )
                )
                db.commit()

                db_cursor.execute("""
                    INSERT INTO user_codeword (user_id, helper_data, codeword, ecc)
                    VALUES (%s, %s, %s, %s)
                    """, (
                        uid, helper_db, commitment.hashed_codeword.hexdigest(), bytes(commitment.ecc)
                    )
                )
                db.commit()

                return {
                    "message":f"User embedding with NIK {nik} successfully registered",
                    "status": 201,
                    'request_received': request_received,
                    'request_data': res
                }, 201
            else:
                db_cursor.execute("""
                    UPDATE user_biometric
                    SET 
                        embedding=%s,
                        last_updated=%s
                    WHERE user_id=%s
                    """, (
                    embedding.tolist(), request_received, uid
                    )
                )
                db.commit()

                db_cursor.execute("""
                    UPDATE user_codeword
                    SET 
                        helper_data=%s,
                        codeword=%s,
                        ecc=%s
                    WHERE user_id=%s
                    """, (
                    helper_db, commitment.hashed_codeword.hexdigest(), bytes(commitment.ecc), uid
                    )
                )
                db.commit()

                return {
                    'status': 200,
                    'message': "Embedding already registered, embedding updated.",
                    'request_received': request_received,
                    'request_data': res
                    }, 200
        except psycopg2.DatabaseError as error:
            logging.error(error)
            raise error
        except TimeoutError as terror:
            logging.error(terror)
            return {
                'status': 408,
                'message': "Timeout error.",
                'error_details': terror,
                'request_received': request_received,
                'request_data': res
                    }, 408
        except Exception as error:
            logging.error(error)
            return {
                'status': 500,
                'message': "Failed to register.",
                'error_details': error,
                'request_received': request_received,
                'request_data': res
                    }, 500
        
@bp.route('/biometric-auth', methods=['POST'], strict_slashes=False)
def authenticate():
    if request.method == 'POST':
        request_received = datetime.now()
        res = get_field(req=request)
        file = request.files['file']

        if file.filename == '':
            return {
                'received_data': {**res, 'filename': file.filename},
                'status': 400,
                'message': "There is some data missing.",
                'error_details': f"(nik, file upload)"
                    }, 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join('flaskr/public', filename))
        
        try:
            model = load_model('flaskr/public/vggface2.h5')
            embedding = get_vector(image_dir=f'flaskr/public/{file.filename}', classifier=model, detect_faces=detect_faces).flatten()
            db=get_existing_db()
            db_cursor = db.cursor(cursor_factory=RealDictCursor)
            db_cursor.execute(
                "SELECT user_id FROM user_biometric where embedding <=> %s <= 0.2", 
                (
                    f'{embedding.tolist()}',
                )
            )
            uid = db_cursor.fetchone()
            if uid == None:
                return {
                'received_data': {**res, 'filename': file.filename},
                'status': 200,
                'message': "No users found."
                    }, 200
            uid = uid.get('user_id', None)
        except Exception as error:
            raise error

        db_cursor.execute("""
            SELECT u.nik, u.full_name, u.BID_identifier, uc.helper_data, uc.ecc, us.account_number, us.issuer_id
            from users u
            join user_codeword uc on u.id = uc.user_id
            join user_sof us on u.id = us.user_id
            where us.default_sof=true and u.id=%s;
            """, 
            (
                uid,
            )
        )
        fetched_user = db_cursor.fetchone()
        signed = hmac.new(
            key=bytes(str(os.getenv('APIKEY')).encode('utf-8')),
            msg=f'{uid} {request_received} artajasa'.encode('utf-8'),
            digestmod=hashlib.sha256
        ).hexdigest()
        
        return {
            'data': {
                'nik': fetched_user.get('nik', None),
                'full_name': fetched_user.get('full_name', None),
                'BID_identifier': fetched_user.get('BID_identifier', None),
                'helper_data': fetched_user.get('helper_data', None),
                'ecc': fetched_user.get('ecc', None),
                'account_number': fetched_user.get('account_number', None),
                'issuer_id': fetched_user.get('issuer_id', None)
            },
            'status': 200,
            'request_received': request_received,
            'signature': signed
        }, 200