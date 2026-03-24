FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Place the flag where solvers need to find it
COPY flag.txt /flag.txt

# Remove flag from app directory so it's not trivially accessible
RUN rm -f /app/flag.txt

EXPOSE 5000

CMD ["python", "app.py"]
