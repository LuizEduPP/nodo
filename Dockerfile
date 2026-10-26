FROM python:3.14-slim

WORKDIR /app
COPY pyproject.toml .
COPY src src
RUN pip install --no-cache-dir .

ENV XDG_DATA_HOME=/var/lib
EXPOSE 9400/tcp
EXPOSE 9400/udp
CMD ["python", "-m", "nodo"]
