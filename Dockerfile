FROM python:3.8-alpine

LABEL org.opencontainers.image.description="A Dockerized URL shortener application written in Flask."

WORKDIR /app

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app", "-w", "2", "--threads", "2" ]
