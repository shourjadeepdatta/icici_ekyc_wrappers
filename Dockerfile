# main image for the application
FROM python:3.8-slim-buster

# installing binaries for the code
RUN apt-get update
RUN apt-get install ffmpeg libsm6 libxext6  -y

# Install Chrome and Chrome WebDriver
RUN apt-get install -y \
    wget \
    curl \
    unzip \
    gnupg


# Download chrome
# Adding trusting keys to apt for repositories

# Updating apt to see and install Google Chrome
RUN apt-get -y update


WORKDIR /app

# install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:5557 --workers 1 'app:app'"]
