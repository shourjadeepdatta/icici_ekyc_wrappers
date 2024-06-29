from app import app
from flask_cors import CORS
import os


CORS(app, methods=['GET', 'POST'])


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)#5000