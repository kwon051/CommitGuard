FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY templates/ templates/
COPY samples/ samples/
CMD ["flask", "run", "--host", "0.0.0.0", "--port", "5000"]