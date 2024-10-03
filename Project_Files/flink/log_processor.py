from pyflink.datastream import StreamExecutionEnvironment
from pyflink.table import StreamTableEnvironment, EnvironmentSettings
from pyflink.table.expressions import col


def log_processing():
    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_parallelism(1)
    settings = EnvironmentSettings.new_instance().in_streaming_mode().build()
    t_env = StreamTableEnvironment.create(env, environment_settings=settings)

    # Kafka source
    t_env.execute_sql("""
        CREATE TABLE kafka_source (
            log_id STRING,
            `timestamp` TIMESTAMP(3),
            client_ip STRING,
            method STRING,
            url STRING,
            status_code INT,
            response_time_ms BIGINT,
            bytes_sent BIGINT,
            bytes_received BIGINT,
            user_agent STRING,
            referer STRING,
            request_headers STRING,
            response_headers STRING,
            geo STRING,
            request_body STRING
        ) WITH (
            'connector' = 'kafka',
            'topic' = 'normal-logs,threat-logs',
            'properties.bootstrap.servers' = 'kafka:9092',
            'properties.group.id' = 'flink-consumer-group',
            'format' = 'json',
            'scan.startup.mode' = 'latest-offset'
        )
    """)

    # Elasticsearch sink
    t_env.execute_sql("""
        CREATE TABLE elasticsearch_sink (
            log_id STRING,
            `timestamp` TIMESTAMP(3),
            client_ip STRING,
            method STRING,
            url STRING,
            status_code INT,
            response_time_ms BIGINT,
            bytes_sent BIGINT,
            bytes_received BIGINT,
            user_agent STRING,
            referer STRING,
            request_headers STRING,
            response_headers STRING,
            geo STRING,
            request_body STRING
        ) WITH (
            'connector' = 'elasticsearch-7',
            'hosts' = 'http://elasticsearch:9200',
            'index' = 'logs-index'
        )
    """)

    # Execute the job
    t_env.from_path('kafka_source').execute_insert('elasticsearch_sink')


if __name__ == '__main__':
    log_processing()