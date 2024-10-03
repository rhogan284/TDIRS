FROM flink:1.17.1

# Install wget
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*

# Download Kafka connector
RUN wget https://repo1.maven.org/maven2/org/apache/flink/flink-sql-connector-kafka/1.17.1/flink-sql-connector-kafka-1.17.1.jar -P /opt/flink/lib/

# Download Elasticsearch connector (using 1.15.4 version which should be compatible)
RUN wget https://repo1.maven.org/maven2/org/apache/flink/flink-connector-elasticsearch7_2.12/1.15.4/flink-connector-elasticsearch7_2.12-1.15.4.jar -P /opt/flink/lib/

# Install Python and pip
RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

# Install PyFlink
RUN pip3 install apache-flink==1.17.1

COPY log_processor.py /opt/flink/log_processor.py