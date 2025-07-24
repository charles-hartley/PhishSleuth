PhishSleuth Django Backend Setup
Run these commands to create the project structure

1. Create Django project and app
django-admin startproject phishsleuth_backend
cd phishsleuth_backend
python manage.py startapp scanner

2. Install required packages
pip install django transformers torch scikit-learn python-magic-bin email-validator

3. Project structure will look like:

phishsleuth_backend/
├── manage.py
├── phishsleuth_backend/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
└── scanner/
    ├── __init__.py
    ├── admin.py
    ├── apps.py
    ├── models.py
    ├── views.py
    ├── urls.py
    ├── utils/
    │   ├── __init__.py
    │   ├── phishing_detector.py
    │   ├── file_processor.py
    │   └── url_analyzer.py
    ├── templates/
    │   └── scanner/
    │       └── index.html
    └── static/
        └── scanner/
            ├── css/
            │   └── style.css
            ├── js/
            │   └── main.js
            └── images/
