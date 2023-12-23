FROM python:3.9-slim

WORKDIR /app

COPY . .

RUN pip install --user -r requirements.txt

RUN pip install gunicorn

# Download the model first
RUN python model.py

ENV PORT=8080
ENV HOST=0.0.0.0
ENV FLASK_ENV=production

EXPOSE ${PORT}

CMD gunicorn -w 4 -b ${HOST}:${PORT} app:app --timeout 120 --graceful-timeout 120