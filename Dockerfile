FROM python:3.8-slim

WORKDIR /app

COPY . /app

EXPOSE 443
EXPOSE 80


RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir gunicorn

RUN apt-get update
RUN apt-get install -y openssl

RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx.key -out /etc/ssl/certs/nginx.crt -subj "/C=PL/ST=Mazovian/L=Warsaw/O=PW/CN=localhost"
RUN chmod 600 /etc/ssl/certs/nginx.crt
RUN chmod 600 /etc/ssl/private/nginx.key

CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:create_app()"]
