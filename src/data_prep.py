"""Backward-compatible alias for CSV testing producer.

Old project used this file for feature preprocessing.
New pipeline sends raw CSV rows to Kafka for testing.
"""

from src.kafka_producer_csv import main


if __name__ == "__main__":
	main()

