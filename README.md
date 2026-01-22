# 🦷 OdontoCare - Sistema de Gestión Dental

**OdontoCare** es una aplicación backend completa para la gestión de clínicas dentales, desarrollada como microservicios con Flask. Permite administrar pacientes, doctores, centros médicos y citas de manera eficiente y segura.

## 🎯 Características Principales

- **Arquitectura Modular**: Organizada en tres Blueprints (auth_bp, admin_bp, citas_bp) para separación de responsabilidades
- **Persistencia de Datos**: Base de datos SQLite con SQLAlchemy ORM para gestión de entidades y relaciones
- **Seguridad**: Autenticación basada en tokens JWT para acceso controlado a recursos
- **API RESTful**: Endpoints JSON para operaciones CRUD con validación de datos y manejo de errores
- **Contenerización**: Servicios desplegados como contenedores Docker para portabilidad y escalabilidad
- **Cliente Externo**: Script `carga_inicial.py` para interacción con la API

## 🚀 Inicio Rápido

```bash
# Clonar repositorio
git clone <repositorio>

# Ejecutar con Docker (recomendado)
docker-compose up --build

# O ejecutar localmente
python -m odontocare.admin_service.app  # Puerto 8000
python -m odontocare.citas_service.app    # Puerto 8001
```

## 📡 API Endpoints

- **Auth Service** (http://localhost:8000): Registro, login y gestión de usuarios
- **Admin Service** (http://localhost:8000): CRUD de pacientes, doctores y centros
- **Citas Service** (http://localhost:8001): Gestión completa de citas médicas

El proyecto integra todos los conceptos del curso C1: HTTP, Flask, bases de datos, autenticación y microservicios, siguiendo buenas prácticas de ingeniería de software.