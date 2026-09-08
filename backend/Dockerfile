FROM python:3.12-slim

WORKDIR /app
COPY analyzer /src/analyzer
COPY backend /src/backend
RUN python -m pip install --no-cache-dir /src/analyzer /src/backend

ENV TEA121_DATABASE_URL=sqlite:///./data/tea121.db \
    TEA121_STORAGE_DIR=./data/files \
    TEA121_ANALYZER_COMMAND=tea121
RUN mkdir -p /app/data
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
