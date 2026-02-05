# ===========================================
# Dockerfile for ScamRakshak
# ===========================================
# This file tells Docker how to build a container for our app.
# Think of it as a recipe: "Here's how to set up a computer to run my app"

# Step 1: Start with a base image (Python 3.11)
# This is like saying "Start with a computer that already has Python installed"
FROM python:3.11-slim

# Step 2: Set the working directory inside the container
# This is like saying "Create a folder called /app and work from there"
WORKDIR /app

# Step 3: Copy requirements.txt first (for caching)
# Docker caches steps - if requirements.txt doesn't change,
# it won't reinstall packages every time
COPY requirements.txt .

# Step 4: Install Python dependencies
# --no-cache-dir means "don't store download cache" (saves space)
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Copy the rest of the application code
# This copies everything from your project folder into the container
COPY . .

# Step 6: Expose the port
# This tells Docker "the app will use this port"
# Railway/Render will set the PORT environment variable
EXPOSE 8000

# Step 7: Define the command to run the app
# When the container starts, run this command
# ${PORT:-8000} means "use PORT if set, otherwise use 8000"
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
