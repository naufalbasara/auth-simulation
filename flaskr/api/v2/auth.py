import logging, io, psycopg2, hashlib, random, os, base64, numpy as np, hmac
logging.basicConfig(level=logging.INFO, format=' %(asctime)s -  %(levelname)s:  %(message)s')

from datetime import datetime, timedelta
from flask import request, Blueprint, redirect, current_app, jsonify
from flaskr.api.v1.auth import check_status, check_unique, handle_register
from flaskr.db import get_existing_db
from flaskr.ext.utils import get_field, load_model, get_vector, detect_faces
from flaskr.ext.fcs import FCS
from flask_jwt_extended import create_access_token
from PIL import Image
from psycopg2.extras import RealDictCursor
from werkzeug.utils import secure_filename

bp = Blueprint('auth', __name__, url_prefix='/auth')
bp.route('/check-status', methods=['POST'], strict_slashes=False, function=check_status)
bp.route('/register', methods=['POST'], strict_slashes=False, function=handle_register)

@bp.route('/register-biometeric', methods=['POST'], strict_slashes=False)
def register_biometric():
    if request.method == 'POST':
        request_received = datetime.now()
        res = get_field(req=request)
        nik = res.get('nik', None)
        b64image = res.get('b64image', None)
        db = get_existing_db()
        
        if nik == None or b64image == None:
            return {
                'received_data': res,
                'status': 400,
                'message': f"There is some data missing.",
                'error_details': f"(nik, base64Image)"
            }, 400
        
        try:
            image = base64.b64decode(b64image)
            Image.open(image).save(os.path.join('flaskr/public', 'captured.JPEG'))
        except:
            return {
                'received_data': res,
                'status': 400,
                'message': f"Not a valid base64 format.",
                'error_details': f"(base64Image)"
            }, 400

        uid=check_unique(db, 'users', 'nik', nik)

        if uid == None:
            return {
                'received_data': res,
                'status': 200,
                'message': f"User with {nik} not exists.",
                'error_details': f"(nik, file upload)"
                }, 200
        try:
            uid = uid.get('id', None)
            model = load_model('flaskr/public/vggface2.h5')
            db_cursor = db.cursor(cursor_factory=RealDictCursor)
            embedding_check=check_unique(db, 'user_biometric', 'user_id', uid)
            embedding = get_vector(image_dir=f'flaskr/public/captured.JPEG', classifier=model, detect_faces=detect_faces).flatten()
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
    
    return