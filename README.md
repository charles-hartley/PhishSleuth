PhishSleuth — AI-Powered Phishing Detection Platform

PhishSleuth is a lightweight, AI-driven web platform for detecting, analyzing, and visualizing phishing threats in real time. It empowers users to upload suspicious emails, URLs, or text and receive instant threat analysis powered by transformers, traditional ML models, and rule-based logic — all wrapped in an intuitive, animated UI.

Live Demo

Try It on Render (https://phishsleuth-2ah2.onrender.com)

Features

-Multi-Mode Threat Input: Analyze text, file (email), or URL via tabbed input.
-Hybrid Detection Engine:
  - HuggingFace zero-shot transformers
  - Traditional ML classifiers
  - Rule-based heuristics
-Dynamic Results:
  - Threat classification and severity
  - Highlighted risky elements (e.g., suspicious links)
-Real-Time Visualization:
  - Animated result display
  - Phishing matrix background + terminal style text effects
-Stats & History:
  - Live statistics (e.g., phishing vs. safe scan counts)
  - Historical scan logs
-  AJAX Backend Integration: All scans use `fetch` API for seamless real-time interaction.
- Secure Django Backend with organized `scanner` app
- Custom Frontend using Vanilla JS + Bootstrap + CSS animations

---

 Tech Stack

Backend:
- `Django` (REST integrated, modular design)
- `Python` with `scikit-learn`, `transformers`, `nltk`, `re`, `joblib`

Frontend:
- HTML5, CSS3, Bootstrap
- Vanilla JavaScript (custom class: `PhishSleuth`)
- Matrix animation & terminal UI

 Detection Pipeline

1. Preprocessing — Tokenization, cleaning, URL extraction
2. Model Inference — Multiple classifiers + transformers
3. Rule Matching — Regex + heuristic checks
4. Score Aggregation — Final threat level and justification


Project Structure

.
├── phishsleuth_backend/
│   └── settings, urls, wsgi
├── scanner/
│   ├── static/        # JS, CSS, matrix animations
│   ├── templates/     # index.html + tabs
│   ├── views.py       # AJAX endpoints
│   ├── urls.py
│   ├── utils/         # phishing_detector.py, file_processor.py, url_analyzer.py
│   ├── serializers.py
│   └── models.py
└── manage.py

