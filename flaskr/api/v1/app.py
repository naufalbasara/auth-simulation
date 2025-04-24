import logging
logging.basicConfig(level=logging.INFO, format=' %(asctime)s -  %(levelname)s:  %(message)s')

from datetime import datetime, timedelta
from flask import request, Blueprint
from flaskr.api.v1.auth import bp as bpAuth

bp = Blueprint('v1', __name__, url_prefix='/v1')
bp.register_blueprint(bpAuth)