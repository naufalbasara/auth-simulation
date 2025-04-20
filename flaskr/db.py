import logging, os, psycopg2, click
logging.basicConfig(level=logging.INFO, format=' %(asctime)s -  %(levelname)s:  %(message)s')

from datetime import datetime
from flask import current_app, g

def get_existing_db():
    database = os.environ.get('DB_DATABASE')
    username = os.environ.get('DB_USER')
    password = os.environ.get('DB_PASS')
    host = os.environ.get('DB_HOST')
    port = os.environ.get('DB_PORT')

    g.db = psycopg2.connect(
        dbname=database, user=username, password=password, host=host, port=port
    )

    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()
    return

def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)

@click.command('init-db')
def init_db_command():
    db = get_existing_db()
    with current_app.open_resource('schema.sql', 'r') as f:
        db.cursor().execute(
            f.read()
        )
        db.commit()

    click.echo("Database initialized.")
    return