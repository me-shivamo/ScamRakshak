# Procfile for Railway/Render
# This tells the platform how to start the application
# web: means "this is a web server"
# uvicorn: the server that runs FastAPI
# app.main:app: find the 'app' object in app/main.py
# --host 0.0.0.0: listen on all network interfaces
# --port $PORT: use the PORT environment variable (set by Railway/Render)

web: uvicorn app.main:app --host 0.0.0.0 --port $PORT
