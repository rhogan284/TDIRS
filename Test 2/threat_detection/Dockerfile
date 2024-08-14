FROM python:3.12
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY threat_detection.py .
CMD ["python", "threat_detection.py"]