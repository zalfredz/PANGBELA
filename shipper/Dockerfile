FROM python:3.12.8-slim
WORKDIR /app
COPY shipper.py .
# -u: log lines reach `docker compose logs` immediately.
CMD ["python", "-u", "shipper.py"]
