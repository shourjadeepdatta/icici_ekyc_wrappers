from flask import Flask
from app.routes import bp as camsBlueprint
# import logging

app = Flask(__name__)

app.register_blueprint(camsBlueprint)

