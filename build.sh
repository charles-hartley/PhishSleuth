#!/usr/bin/env bash
# build.sh

# Navigate to the Django project directory
cd phishsleuth_backend

# Install dependencies
pip install -r ../requirements.txt

# Run Django commands
python manage.py collectstatic --noinput
<<<<<<< HEAD
python manage.py migrate
=======
python manage.py migrate
>>>>>>> 69e57188e920da9f20f3976077ba951c0134da9b
