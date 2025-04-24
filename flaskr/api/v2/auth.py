import logging, psycopg2, hashlib, random, os, base64, numpy as np, hmac
logging.basicConfig(level=logging.INFO, format=' %(asctime)s -  %(levelname)s:  %(message)s')

from datetime import datetime, timedelta
from flask import request, Blueprint, redirect, current_app, jsonify
from flaskr.api.v1.auth import check_status, check_unique, handle_register
from flaskr.db import get_existing_db
from flaskr.ext.utils import get_field, load_model, get_vector, detect_faces
from flaskr.ext.fcs import FCS
from flask_jwt_extended import create_access_token
from psycopg2.extras import RealDictCursor
from werkzeug.utils import secure_filename

bp = Blueprint('auth', __name__, url_prefix='/auth')
bp.route('/check-status', methods=['POST'], strict_slashes=False, function=check_status)
bp.route('/register', methods=['POST'], strict_slashes=False, function=handle_register)
