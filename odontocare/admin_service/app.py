# Servicio de Administradores - OdontoCare
# ========================================
# - Hash de contraseñas
# - CRUD completo para pacientes, doctores y centros
# - Autenticación JWT

import os
from datetime import timedelta
from typing import Optional

from flask import Blueprint, Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

# Configuración de la aplicación Flask
app = Flask(__name__)

# Configuración de la base de datos SQLite
DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///admin_service.db")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Configuración de JWT
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "clave-secreta-cambiar-en-produccion")
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

# Inicialización de extensiones
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

# Códigos de estado HTTP
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_NO_CONTENT = 204
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_UNPROCESSABLE_ENTITY = 422

# Estados de entidad
ESTADO_ACTIVO = "ACTIVO"
ESTADO_INACTIVO = "INACTIVO"

# Roles de usuario
ROL_ADMIN = "admin"
ROL_MEDICO = "medico"
ROL_SECRETARIA = "secretaria"
ROL_PACIENTE = "paciente"

# MODELOS DE DATOS (SQLAlchemy)


class User(db.Model):
    """Modelo de usuario para autenticación"""

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    rol = db.Column(
        db.String(20), nullable=False
    )  # admin, medico, secretaria, paciente


class Patient(db.Model):
    """Modelo de paciente"""

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    telefono = db.Column(db.String(20))
    estado = db.Column(db.String(20), default="ACTIVO")  # ACTIVO/INACTIVO
    id_usuario = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


class Doctor(db.Model):
    """Modelo de doctor"""

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    especialidad = db.Column(db.String(50))
    estado = db.Column(db.String(20), default="ACTIVO")  # ACTIVO/INACTIVO
    id_usuario = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


class Center(db.Model):
    """Modelo de centro médico"""

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    direccion = db.Column(db.String(200))
    estado = db.Column(db.String(20), default="ACTIVO")  # ACTIVO/INACTIVO


# HELPER FUNCTIONS
# ================


def require_admin() -> Optional[User]:
    """Verifica que el usuario actual exista y sea admin.

    Returns:
        User: El usuario autenticado con rol admin, None si no cumple.
    """
    user_id = get_jwt_identity()
    if user_id is None:
        return None

    usuario_actual = User.query.get(int(user_id))
    if not usuario_actual or usuario_actual.rol != ROL_ADMIN:
        return None
    return usuario_actual


def paginate_query(query):
    """Aplica paginación estándar a una query SQLAlchemy.

    Args:
        query: Query de SQLAlchemy a paginar.

    Returns:
        Objeto de paginación de SQLAlchemy.
    """
    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=10, type=int)
    per_page = min(max(per_page, 1), 100)
    return query.paginate(page=page, per_page=per_page, error_out=False)


def build_meta(pagination):
    return {
        "page": pagination.page,
        "per_page": pagination.per_page,
        "total": pagination.total,
        "pages": pagination.pages,
    }


# BLUEPRINT: auth_bp (Autenticación)

auth_bp = Blueprint("auth_bp", __name__)


@auth_bp.route("/auth/register", methods=["POST"])
def register():
    """Registrar un nuevo usuario"""
    data = request.get_json() or {}

    if "username" not in data or "password" not in data:
        return jsonify({"error": "Faltan datos requeridos"}), 400

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "El usuario ya existe"}), 400

    hashed = generate_password_hash(data["password"])
    nuevo_usuario = User(
        username=data["username"],
        password=hashed,
        rol=data.get("rol", ROL_PACIENTE),
    )
    db.session.add(nuevo_usuario)
    db.session.commit()

    return (
        jsonify(
            {
                "mensaje": "Usuario creado exitosamente",
                "usuario": {
                    "id": nuevo_usuario.id,
                    "username": nuevo_usuario.username,
                    "rol": nuevo_usuario.rol,
                },
            }
        ),
        HTTP_CREATED,
    )


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    """Iniciar sesión y obtener token JWT"""
    data = request.get_json() or {}

    if "username" not in data or "password" not in data:
        return jsonify({"error": "Faltan datos requeridos"}), 400

    usuario = User.query.filter_by(username=data["username"]).first()
    if not usuario or not check_password_hash(usuario.password, data["password"]):
        return jsonify({"error": "Credenciales inválidas"}), 401

    token = create_access_token(identity=str(usuario.id))

    return (
        jsonify(
            {
                "mensaje": "Login exitoso",
                "access_token": token,
                "usuario": {
                    "id": usuario.id,
                    "username": usuario.username,
                    "rol": usuario.rol,
                },
            }
        ),
        HTTP_OK,
    )


@auth_bp.route("/auth/verify", methods=["GET"])
@jwt_required()
def verify_token():
    """Verificar que un token JWT sea válido (usado por otros servicios).

    Returns:
        Tuple[Response, int]: Respuesta JSON con validación y datos del usuario.
    """
    user_id = get_jwt_identity()
    usuario = User.query.get(int(user_id))

    if usuario:
        return (
            jsonify(
                {
                    "valid": True,
                    "user_id": usuario.id,
                    "username": usuario.username,
                    "rol": usuario.rol,
                }
            ),
            HTTP_OK,
        )
    return jsonify({"valid": False, "error": "Usuario no encontrado"}), HTTP_NOT_FOUND


# BLUEPRINT: verify_bp (Verificación para otros servicios)

verify_bp = Blueprint("verify_bp", __name__)


@verify_bp.route("/verify/pacientes/<int:paciente_id>", methods=["GET"])
@jwt_required()
def verificar_paciente(paciente_id):
    """Verificar si existe un paciente activo (usado por citas_service).

    Args:
        paciente_id: ID del paciente a verificar.

    Returns:
        Tuple[Response, int]: Respuesta JSON con información de existencia y código HTTP.
    """
    paciente = Patient.query.filter_by(id=paciente_id, estado=ESTADO_ACTIVO).first()

    if not paciente:
        return (
            jsonify({"exists": False, "error": "Paciente no encontrado o inactivo"}),
            HTTP_NOT_FOUND,
        )

    return jsonify({"exists": True, "id": paciente.id}), HTTP_OK


@verify_bp.route("/verify/doctores/<int:doctor_id>", methods=["GET"])
@jwt_required()
def verificar_doctor(doctor_id):
    """Verificar si existe un doctor activo (usado por citas_service).

    Args:
        doctor_id: ID del doctor a verificar.

    Returns:
        Tuple[Response, int]: Respuesta JSON con información de existencia y código HTTP.
    """
    doctor = Doctor.query.filter_by(id=doctor_id, estado=ESTADO_ACTIVO).first()

    if not doctor:
        return (
            jsonify({"exists": False, "error": "Doctor no encontrado o inactivo"}),
            HTTP_NOT_FOUND,
        )

    return jsonify({"exists": True, "id": doctor.id}), HTTP_OK


@verify_bp.route("/verify/centros/<int:centro_id>", methods=["GET"])
@jwt_required()
def verificar_centro(centro_id):
    """Verificar si existe un centro activo (usado por citas_service).

    Args:
        centro_id: ID del centro a verificar.

    Returns:
        Tuple[Response, int]: Respuesta JSON con información de existencia y código HTTP.
    """
    centro = Center.query.filter_by(id=centro_id, estado=ESTADO_ACTIVO).first()

    if not centro:
        return (
            jsonify({"exists": False, "error": "Centro no encontrado o inactivo"}),
            HTTP_NOT_FOUND,
        )

    return jsonify({"exists": True, "id": centro.id}), HTTP_OK


@verify_bp.route("/verify/token", methods=["GET"])
@jwt_required()
def verify_token_endpoint():
    """Verificar que un token JWT sea válido (endpoint alternativo para compatibilidad).

    Returns:
        Tuple[Response, int]: Respuesta JSON con validación y datos del usuario.
    """
    user_id = get_jwt_identity()
    usuario = User.query.get(int(user_id))

    if usuario:
        return (
            jsonify(
                {
                    "valid": True,
                    "user_id": usuario.id,
                    "username": usuario.username,
                    "rol": usuario.rol,
                }
            ),
            HTTP_OK,
        )
    return jsonify({"valid": False, "error": "Usuario no encontrado"}), HTTP_NOT_FOUND


# BLUEPRINT: admin_bp (Administración)

admin_bp = Blueprint("admin_bp", __name__)

# -------- Pacientes ---------


@admin_bp.route("/admin/pacientes", methods=["POST"])
@jwt_required()
def crear_paciente():
    """Crear un nuevo paciente (requiere rol admin).

    Returns:
        Tuple[Response, int]: Respuesta JSON y código de estado HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    data = request.get_json() or {}
    if "nombre" not in data:
        return jsonify({"error": "Faltan datos requeridos"}), HTTP_BAD_REQUEST

    nuevo_paciente = Patient(
        nombre=data["nombre"],
        telefono=data.get("telefono", ""),
        estado=data.get("estado", ESTADO_ACTIVO),
    )
    db.session.add(nuevo_paciente)
    db.session.commit()

    return (
        jsonify(
            {
                "mensaje": "Paciente creado exitosamente",
                "paciente": {
                    "id": nuevo_paciente.id,
                    "nombre": nuevo_paciente.nombre,
                    "telefono": nuevo_paciente.telefono,
                    "estado": nuevo_paciente.estado,
                },
            }
        ),
        HTTP_CREATED,
    )


@admin_bp.route("/admin/pacientes", methods=["GET"])
@jwt_required()
def listar_pacientes():
    """Listar pacientes con filtros y paginación (solo activos por defecto).

    Returns:
        Tuple[Response, int]: Respuesta JSON con pacientes y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    estado = request.args.get("estado", default=ESTADO_ACTIVO)
    nombre = request.args.get("nombre")

    query = Patient.query
    if estado:
        query = query.filter_by(estado=estado)
    if nombre:
        query = query.filter(Patient.nombre.ilike(f"%{nombre}%"))

    pagination = paginate_query(query.order_by(Patient.id))
    pacientes = [
        {
            "id": p.id,
            "nombre": p.nombre,
            "telefono": p.telefono,
            "estado": p.estado,
        }
        for p in pagination.items
    ]

    return jsonify({"pacientes": pacientes, "meta": build_meta(pagination)}), HTTP_OK


@admin_bp.route("/admin/pacientes/<int:paciente_id>", methods=["GET"])
@jwt_required()
def obtener_paciente(paciente_id):
    """Obtener un paciente específico por ID.

    Args:
        paciente_id: ID del paciente a obtener.

    Returns:
        Tuple[Response, int]: Respuesta JSON con el paciente y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    paciente = Patient.query.get(paciente_id)
    if not paciente:
        return jsonify({"error": "Paciente no encontrado"}), HTTP_NOT_FOUND

    return (
        jsonify(
            {
                "paciente": {
                    "id": paciente.id,
                    "nombre": paciente.nombre,
                    "telefono": paciente.telefono,
                    "estado": paciente.estado,
                }
            }
        ),
        HTTP_OK,
    )


@admin_bp.route("/admin/pacientes/<int:paciente_id>", methods=["PUT"])
@jwt_required()
def actualizar_paciente(paciente_id):
    """Actualizar datos de un paciente (soft delete si estado=INACTIVO).

    Args:
        paciente_id: ID del paciente a actualizar.

    Returns:
        Tuple[Response, int]: Respuesta JSON y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    paciente = Patient.query.get(paciente_id)
    if not paciente:
        return jsonify({"error": "Paciente no encontrado"}), HTTP_NOT_FOUND

    data = request.get_json() or {}
    if "nombre" in data:
        paciente.nombre = data["nombre"]
    if "telefono" in data:
        paciente.telefono = data["telefono"]
    if "estado" in data:
        paciente.estado = data["estado"]

    db.session.commit()

    return (
        jsonify(
            {
                "mensaje": "Paciente actualizado exitosamente",
                "paciente": {
                    "id": paciente.id,
                    "nombre": paciente.nombre,
                    "telefono": paciente.telefono,
                    "estado": paciente.estado,
                },
            }
        ),
        HTTP_OK,
    )


@admin_bp.route("/admin/pacientes/<int:paciente_id>", methods=["DELETE"])
@jwt_required()
def eliminar_paciente(paciente_id):
    """Soft delete de paciente (estado=INACTIVO).

    Args:
        paciente_id: ID del paciente a inactivar.

    Returns:
        Tuple[Response, int]: Respuesta JSON y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    paciente = Patient.query.get(paciente_id)
    if not paciente:
        return jsonify({"error": "Paciente no encontrado"}), HTTP_NOT_FOUND

    paciente.estado = ESTADO_INACTIVO
    db.session.commit()

    return jsonify({"mensaje": "Paciente inactivado exitosamente"}), HTTP_OK


# -------- Doctores ---------


@admin_bp.route("/admin/doctores", methods=["POST"])
@jwt_required()
def crear_doctor():
    """Crear un nuevo doctor (requiere rol admin).

    Returns:
        Tuple[Response, int]: Respuesta JSON y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    data = request.get_json() or {}
    if "nombre" not in data:
        return jsonify({"error": "Faltan datos requeridos"}), HTTP_BAD_REQUEST

    nuevo_doctor = Doctor(
        nombre=data["nombre"],
        especialidad=data.get("especialidad", ""),
        estado=data.get("estado", ESTADO_ACTIVO),
    )
    db.session.add(nuevo_doctor)
    db.session.commit()

    return (
        jsonify(
            {
                "mensaje": "Doctor creado exitosamente",
                "doctor": {
                    "id": nuevo_doctor.id,
                    "nombre": nuevo_doctor.nombre,
                    "especialidad": nuevo_doctor.especialidad,
                    "estado": nuevo_doctor.estado,
                },
            }
        ),
        HTTP_CREATED,
    )


@admin_bp.route("/admin/doctores", methods=["GET"])
@jwt_required()
def listar_doctores():
    """Listar doctores con filtros y paginación.

    Returns:
        Tuple[Response, int]: Respuesta JSON con doctores y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    estado = request.args.get("estado", default=ESTADO_ACTIVO)
    nombre = request.args.get("nombre")
    especialidad = request.args.get("especialidad")

    query = Doctor.query
    if estado:
        query = query.filter_by(estado=estado)
    if nombre:
        query = query.filter(Doctor.nombre.ilike(f"%{nombre}%"))
    if especialidad:
        query = query.filter(Doctor.especialidad.ilike(f"%{especialidad}%"))

    pagination = paginate_query(query.order_by(Doctor.id))
    doctores = [
        {
            "id": d.id,
            "nombre": d.nombre,
            "especialidad": d.especialidad,
            "estado": d.estado,
        }
        for d in pagination.items
    ]

    return jsonify({"doctores": doctores, "meta": build_meta(pagination)}), HTTP_OK


@admin_bp.route("/admin/doctores/<int:doctor_id>", methods=["GET"])
@jwt_required()
def obtener_doctor(doctor_id):
    """Obtener un doctor específico por ID.

    Args:
        doctor_id: ID del doctor a obtener.

    Returns:
        Tuple[Response, int]: Respuesta JSON con el doctor y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    doctor = Doctor.query.get(doctor_id)
    if not doctor:
        return jsonify({"error": "Doctor no encontrado"}), HTTP_NOT_FOUND

    return (
        jsonify(
            {
                "doctor": {
                    "id": doctor.id,
                    "nombre": doctor.nombre,
                    "especialidad": doctor.especialidad,
                    "estado": doctor.estado,
                }
            }
        ),
        HTTP_OK,
    )


@admin_bp.route("/admin/doctores/<int:doctor_id>", methods=["PUT"])
@jwt_required()
def actualizar_doctor(doctor_id):
    """Actualizar datos de un doctor (soft delete si estado=INACTIVO).

    Args:
        doctor_id: ID del doctor a actualizar.

    Returns:
        Tuple[Response, int]: Respuesta JSON y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    doctor = Doctor.query.get(doctor_id)
    if not doctor:
        return jsonify({"error": "Doctor no encontrado"}), HTTP_NOT_FOUND

    data = request.get_json() or {}
    if "nombre" in data:
        doctor.nombre = data["nombre"]
    if "especialidad" in data:
        doctor.especialidad = data["especialidad"]
    if "estado" in data:
        doctor.estado = data["estado"]

    db.session.commit()

    return (
        jsonify(
            {
                "mensaje": "Doctor actualizado exitosamente",
                "doctor": {
                    "id": doctor.id,
                    "nombre": doctor.nombre,
                    "especialidad": doctor.especialidad,
                    "estado": doctor.estado,
                },
            }
        ),
        HTTP_OK,
    )


@admin_bp.route("/admin/doctores/<int:doctor_id>", methods=["DELETE"])
@jwt_required()
def eliminar_doctor(doctor_id):
    """Soft delete de doctor (estado=INACTIVO).

    Args:
        doctor_id: ID del doctor a inactivar.

    Returns:
        Tuple[Response, int]: Respuesta JSON y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    doctor = Doctor.query.get(doctor_id)
    if not doctor:
        return jsonify({"error": "Doctor no encontrado"}), HTTP_NOT_FOUND

    doctor.estado = ESTADO_INACTIVO
    db.session.commit()

    return jsonify({"mensaje": "Doctor inactivado exitosamente"}), HTTP_OK


# -------- Centros ---------


@admin_bp.route("/admin/centros", methods=["POST"])
@jwt_required()
def crear_centro():
    """Crear un nuevo centro médico (requiere rol admin).

    Returns:
        Tuple[Response, int]: Respuesta JSON y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    data = request.get_json() or {}
    if "nombre" not in data:
        return jsonify({"error": "Faltan datos requeridos"}), HTTP_BAD_REQUEST

    nuevo_centro = Center(
        nombre=data["nombre"],
        direccion=data.get("direccion", ""),
        estado=data.get("estado", ESTADO_ACTIVO),
    )
    db.session.add(nuevo_centro)
    db.session.commit()

    return (
        jsonify(
            {
                "mensaje": "Centro creado exitosamente",
                "centro": {
                    "id": nuevo_centro.id,
                    "nombre": nuevo_centro.nombre,
                    "direccion": nuevo_centro.direccion,
                    "estado": nuevo_centro.estado,
                },
            }
        ),
        HTTP_CREATED,
    )


@admin_bp.route("/admin/centros", methods=["GET"])
@jwt_required()
def listar_centros():
    """Listar centros con filtros y paginación.

    Returns:
        Tuple[Response, int]: Respuesta JSON con centros y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    estado = request.args.get("estado", default=ESTADO_ACTIVO)
    nombre = request.args.get("nombre")
    direccion = request.args.get("direccion")

    query = Center.query
    if estado:
        query = query.filter_by(estado=estado)
    if nombre:
        query = query.filter(Center.nombre.ilike(f"%{nombre}%"))
    if direccion:
        query = query.filter(Center.direccion.ilike(f"%{direccion}%"))

    pagination = paginate_query(query.order_by(Center.id))
    centros = [
        {
            "id": c.id,
            "nombre": c.nombre,
            "direccion": c.direccion,
            "estado": c.estado,
        }
        for c in pagination.items
    ]

    return jsonify({"centros": centros, "meta": build_meta(pagination)}), HTTP_OK


@admin_bp.route("/admin/centros/<int:centro_id>", methods=["GET"])
@jwt_required()
def obtener_centro(centro_id):
    """Obtener un centro específico por ID.

    Args:
        centro_id: ID del centro a obtener.

    Returns:
        Tuple[Response, int]: Respuesta JSON con el centro y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    centro = Center.query.get(centro_id)
    if not centro:
        return jsonify({"error": "Centro no encontrado"}), HTTP_NOT_FOUND

    return (
        jsonify(
            {
                "centro": {
                    "id": centro.id,
                    "nombre": centro.nombre,
                    "direccion": centro.direccion,
                    "estado": centro.estado,
                }
            }
        ),
        HTTP_OK,
    )


@admin_bp.route("/admin/centros/<int:centro_id>", methods=["PUT"])
@jwt_required()
def actualizar_centro(centro_id):
    """Actualizar datos de un centro (soft delete si estado=INACTIVO).

    Args:
        centro_id: ID del centro a actualizar.

    Returns:
        Tuple[Response, int]: Respuesta JSON y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    centro = Center.query.get(centro_id)
    if not centro:
        return jsonify({"error": "Centro no encontrado"}), HTTP_NOT_FOUND

    data = request.get_json() or {}
    if "nombre" in data:
        centro.nombre = data["nombre"]
    if "direccion" in data:
        centro.direccion = data["direccion"]
    if "estado" in data:
        centro.estado = data["estado"]

    db.session.commit()

    return (
        jsonify(
            {
                "mensaje": "Centro actualizado exitosamente",
                "centro": {
                    "id": centro.id,
                    "nombre": centro.nombre,
                    "direccion": centro.direccion,
                    "estado": centro.estado,
                },
            }
        ),
        HTTP_OK,
    )


@admin_bp.route("/admin/centros/<int:centro_id>", methods=["DELETE"])
@jwt_required()
def eliminar_centro(centro_id):
    """Soft delete de centro (estado=INACTIVO).

    Args:
        centro_id: ID del centro a inactivar.

    Returns:
        Tuple[Response, int]: Respuesta JSON y código HTTP.
    """
    if not require_admin():
        return jsonify({"error": "No autorizado"}), HTTP_FORBIDDEN

    centro = Center.query.get(centro_id)
    if not centro:
        return jsonify({"error": "Centro no encontrado"}), HTTP_NOT_FOUND

    centro.estado = ESTADO_INACTIVO
    db.session.commit()

    return jsonify({"mensaje": "Centro inactivado exitosamente"}), HTTP_OK


# ENDPOINTS DE HEALTH Y ROOT


@app.route("/health")
def health():
    """Endpoint de verificación de salud del servicio.

    Returns:
        Tuple[Response, int]: Respuesta JSON con estado del servicio y código HTTP.
    """
    return jsonify(
        {"service": "admin_service", "status": "ok", "environment": "development"}
    ), HTTP_OK


@app.route("/")
def root():
    """Endpoint raíz con información del servicio.

    Returns:
        Tuple[Response, int]: Respuesta JSON con información del servicio y código HTTP.
    """
    return jsonify(
        {
            "name": "OdontoCare - Servicio de Gestión de Administradores",
            "version": "1.0.0",
            "endpoints": {
                "auth": "/auth",
                "admin": "/admin",
                "verify": "/verify",
                "health": "/health",
            },
        }
    ), HTTP_OK


# INICIALIZACIÓN

# Registrar blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(verify_bp)
app.register_blueprint(admin_bp)

# Crear tablas de la base de datos
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
