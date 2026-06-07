FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir websockets && \
    useradd -r -s /sbin/nologin -u 1000 neuro
WORKDIR /app
COPY control_server.py ws_proxy.py ./
RUN chown -R neuro:neuro /app
USER neuro
CMD ["python3", "-u", "ws_proxy.py"]
