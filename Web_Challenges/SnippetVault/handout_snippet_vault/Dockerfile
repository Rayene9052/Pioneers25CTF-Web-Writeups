FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends file && rm -rf /var/lib/apt/lists/*
RUN useradd -m ctf
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY views/ ./views/

RUN echo "Pioneers25{fake_flag_for_testing}" > /flag.txt && chmod 444 /flag.txt

USER ctf
EXPOSE 5000
CMD ["python", "app.py"]
