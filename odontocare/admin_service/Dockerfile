# Servicio de Usuarios - Dockerfile simplificado para nivel C1
# Basado en ejercicios del curso Python C1

# Usar imagen oficial de Python
FROM python:3.11-slim

# Definir el directorio de trabajo
WORKDIR /app

# Copiar y instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Instalar curl para health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copiar el código de la aplicación
COPY app.py .

# Exponer el puerto de la aplicación
EXPOSE 8000

# Ejecutar la aplicación Flask
CMD ["python", "app.py"]
