FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir websockets
WORKDIR /app
COPY control_server.py ws_proxy.py ./
CMD ["python3", "-u", "control_server.py"]
