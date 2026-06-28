# Use official lightweight Python image
FROM python:3.12-slim

# Prevent Python from writing .pyc files and buffer stdin/stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy requirements list
COPY requirements.txt .

# Install compiler dependencies and packages
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy all backend source code
COPY . .

# Expose port
EXPOSE 5000

# Run entry point
CMD ["python", "app.py"]
