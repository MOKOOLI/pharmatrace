FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pharmatrace ./pharmatrace
RUN useradd -r -u 10001 app && mkdir /data && chown app /data
USER app
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8000/health')"
CMD ["uvicorn", "pharmatrace.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
