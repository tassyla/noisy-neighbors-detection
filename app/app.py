from flask import Flask, request, has_request_context
import logging
import sys
import json
import time
import random


class JSONFormatter(logging.Formatter):
	"""Simple JSON formatter for log records."""

	def format(self, record):
		record_dict = {
			"timestamp": self.formatTime(record, self.datefmt),
			"level": record.levelname,
			"message": record.getMessage(),
			"tenant_id": getattr(record, "tenant_id", "unknown"),
			"module": record.module,
			"funcName": record.funcName,
			"line": record.lineno,
		}
		if record.exc_info:
			record_dict["exc_info"] = self.formatException(record.exc_info)
		return json.dumps(record_dict, default=str)


class RequestTenantFilter(logging.Filter):
	"""Logging filter that extracts X-Tenant-ID from Flask request and adds as tenant_id."""

	def filter(self, record):
		try:
			if has_request_context():
				tenant = request.headers.get("X-Tenant-ID", "unknown")
			else:
				tenant = "unknown"
		except Exception:
			tenant = "unknown"
		record.tenant_id = tenant
		return True


# Configure root logger: JSON to stdout, include tenant filter
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
# Remove default handlers to avoid duplicate logs
root_logger.handlers = []
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(JSONFormatter())
handler.addFilter(RequestTenantFilter())
root_logger.addHandler(handler)


app = Flask(__name__)


@app.route("/")
def index():
	logging.getLogger().info("Accessing index")
	return "OK", 200


@app.route("/heavy_work")
def heavy_work():
	logger = logging.getLogger()
	logger.info("Heavy work started")

	# Simulate CPU-bound work (non-blocking I/O) with a busy loop
	total = 0
	for i in range(500000):
		total += (i * i) % 7

	# Sleep for a small random time up to 0.1s
	time.sleep(random.random() * 0.1)

	logger.info("Heavy work finished")
	return "Done", 200


if __name__ == "__main__":
	# Run the Flask app
	app.run(host="0.0.0.0", port=5000)
