#!/usr/bin/env bash
# build.sh

# Navigate to the Django project directory
cd phishsleuth_backend

# Install dependencies
pip install -r ../requirements.txt

# Run Django commands
python manage.py collectstatic --noinput
python manage.py migrate
