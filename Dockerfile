FROM python:3.10-slim

ENV PYTHONUNBUFFERED True
ENV APP_HOME /app
WORKDIR $APP_HOME
COPY src ./
COPY requirements.txt .

# Install production dependencies.
RUN pip install --no-cache-dir -r requirements.txt

ENV FLASK_ENV=PRODUCTION

CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 fitbit:app
