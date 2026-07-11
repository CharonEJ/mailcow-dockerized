FROM python:3.12-alpine

RUN adduser -D -H -u 20001 portal \
  && mkdir /data \
  && chown portal:portal /data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py auth.py mailcow.py ratelimit.py store.py validation.py ./
COPY templates/ templates/

USER portal
EXPOSE 8000

# Single worker with threads so the in-memory rate limiter is coherent.
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:8000", \
     "--access-logfile", "-", "app:app"]
