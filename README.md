# CyberSecure

This project simulates an e-commerce platform with integrated logging and monitoring using the ELK (Elasticsearch, Logstash, Kibana) stack. It includes both normal user traffic simulation and potential security threat simulations.

## Project Structure

```
.
├── db/
│   └── init.sql
├── locust/
│   ├── locustfile.py
│   └── threat_locustfile.py
├── logstash/
│   ├── logstash.conf
│   └── logstash.yml
├── web/
│   ├── app.py
│   ├── Dockerfile
│   └── requirements.txt
└── docker-compose.yml
```

## Components

1. **Web Application**: A simple Flask-based e-commerce API.
2. **Database**: PostgreSQL database to store product information.
3. **Load Testing**: Two Locust instances for simulating normal user traffic and potential security threats.
4. **ELK Stack**: 
   - Elasticsearch for storing and indexing logs
   - Logstash for log processing and ingestion
   - Kibana for log visualization and analysis

## Setup and Running

1. Ensure you have Docker and Docker Compose installed on your system.

2. Clone this repository:
   ```
   git clone <repository-url>
   cd <repository-directory>
   ```

3. Start the services:
   ```
   docker-compose up -d
   ```

4. Access the components:
   - Web API: http://localhost:5002
   - Kibana: http://localhost:5601
   - Locust (normal traffic): http://localhost:8089
   - Locust (threat simulation): http://localhost:8090

## Usage

1. **Web Application**: 
   - The Flask app provides basic e-commerce endpoints like product listing, cart management, and checkout.

2. **Load Testing**:
   - Use the Locust web interfaces to start and manage load tests.
   - Normal traffic simulation: http://localhost:8089
   - Threat simulation: http://localhost:8090

3. **Log Analysis**:
   - Access Kibana at http://localhost:5601
   - Set up index patterns for "locust-logs-*"
   - Create visualizations and dashboards to analyze the simulated traffic and potential security threats
