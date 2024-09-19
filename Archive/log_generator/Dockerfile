FROM python:3.12
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY log_generator.py .
CMD ["python", "log_generator.py"]