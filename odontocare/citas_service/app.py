# Servicio de Citas Médicas - OdontoCare
# =====================================
# Gestión de citas médicas con comunicación entre servicios

import os
from datetime import datetime
from typing import Optional

import requests
from flask import Blueprint, Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    get_jwt_identity,
    jwt_required,
)
from flask_sqlalchemy import SQLAlchemy

# Configuración de la aplicación Flask
app = Flask(__name__)

# Configuración de la base de datos SQLite
DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///citas_service.db")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Configuración de JWT
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "clave-secreta-cambiar-en-produccion")
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY

# URL del servicio de usuarios (para comunicación entre servicios)
ADMIN_SERVICE_URL = os.getenv("ADMIN_SERVICE_URL", "http://admin_service:8000")

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

# Estados de cita
ESTADO_PROGRAMADA = "PROGRAMADA"
ESTADO_COMPLETADA = "COMPLETADA"
ESTADO_CANCELADA = "CANCELADA"

# Roles de usuario (deben coincidir con admin_service)
ROL_ADMIN = "admin"
ROL_MEDICO = "medico"
ROL_SECRETARIA = "secretaria"
ROL_PACIENTE = "paciente"

# Timeout para peticiones HTTP
REQUEST_TIMEOUT = 5


# MODELO DE DATOS (SQLAlchemy)


class Appointment(db.Model):
    """Modelo de cita médica"""

    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.DateTime, nullable=False)
    motivo = db.Column(db.String(200), nullable=False)
    estado = db.Column(
        db.String(20), default=ESTADO_PROGRAMADA
    )  # PROGRAMADA, COMPLETADA, CANCELADA

    # Claves foráneas
    id_paciente = db.Column(db.Integer, nullable=False)
    id_doctor = db.Column(db.Integer, nullable=False)
    id_centro = db.Column(db.Integer, nullable=False)
    id_usuario_registra = db.Column(db.Integer, nullable=False)


# BLUEPRINT: citas_bp (Gestión de Citas)

citas_bp = Blueprint("citas_bp", __name__)


def verificar_usuario(
    token: str,
) -> tuple[bool, Optional[dict], Optional[int], Optional[str]]:
    """Verificar token y obtener información del usuario desde el servicio de usuarios.

    Args:
        token: Token JWT a verificar.

    Returns:
        tuple[bool, dict|None, int|None, str|None]:
            - success: True si el token es válido
            - usuario: Información del usuario (id, username, rol) si válido
            - status_code: Código de estado HTTP de la respuesta (si aplica)
            - error: Mensaje de error si hubo algún problema
    """
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(
            f"{ADMIN_SERVICE_URL}/auth/verify", headers=headers, timeout=REQUEST_TIMEOUT
        )

        # Verificar que response no sea None antes de usarlo
        if response is None:
            return False, None, None, "No se recibió respuesta del servidor"

        if response.status_code == HTTP_OK:
            try:
                return True, response.json(), response.status_code, None
            except ValueError as e:
                return (
                    False,
                    None,
                    response.status_code,
                    f"Error al procesar respuesta JSON: {str(e)}",
                )
        elif response.status_code == HTTP_UNAUTHORIZED:
            return False, None, response.status_code, "Token inválido o expirado"
        elif response.status_code == HTTP_FORBIDDEN:
            return False, None, response.status_code, "Acceso denegado"
        else:
            return (
                False,
                None,
                response.status_code,
                f"Error al verificar token: {response.status_code}",
            )
    except requests.RequestException as e:
        return False, None, None, f"Error de conexión con admin_service: {str(e)}"


def verificar_existencia_user_service(
    endpoint: str, auth_header: str, return_response: bool = False
) -> bool | tuple[bool, Optional[requests.Response]]:
    """Verificar que una entidad exista en el servicio de usuarios usando endpoints /verify/*.

    Args:
        endpoint: Endpoint a verificar (ej: /verify/pacientes/1).
        auth_header: Header de autorización completo.
        return_response: Si es True, devuelve (success: bool, response) en lugar de solo bool.

    Returns:
        bool: True si la entidad existe, False en caso contrario.
        O (bool, response): Si return_response es True.
    """
    try:
        headers = {"Authorization": auth_header}
        response = requests.get(
            f"{ADMIN_SERVICE_URL}{endpoint}", headers=headers, timeout=REQUEST_TIMEOUT
        )
        if return_response:
            return response.status_code == HTTP_OK, response
        return response.status_code == HTTP_OK
    except requests.RequestException:
        if return_response:
            return False, None
        return False


def obtener_datos_paciente(
    paciente_id: int, auth_header: str
) -> tuple[bool, Optional[dict], Optional[int], Optional[str]]:
    """Obtener datos completos de un paciente para verificar su estado.

    Args:
        paciente_id: ID del paciente a consultar.
        auth_header: Header de autorización completo.

    Returns:
        tuple[bool, dict|None, int|None, str|None]:
            - success: True si el paciente existe y está activo
            - paciente: Datos del paciente si existe, None en caso contrario
            - status_code: Código de estado HTTP de la respuesta (si aplica)
            - error: Mensaje de error si hubo algún problema
    """
    try:
        headers = {"Authorization": auth_header}
        response = requests.get(
            f"{ADMIN_SERVICE_URL}/admin/pacientes/{paciente_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        # Verificar que response no sea None antes de usarlo
        if response is None:
            return False, None, None, "No se recibió respuesta del servidor"

        if response.status_code == HTTP_OK:
            try:
                return True, response.json().get("paciente"), response.status_code, None
            except (ValueError, KeyError) as e:
                return (
                    False,
                    None,
                    response.status_code,
                    f"Error al procesar respuesta JSON: {str(e)}",
                )
        elif response.status_code == HTTP_UNAUTHORIZED:
            return (
                False,
                None,
                response.status_code,
                "No autorizado para acceder al paciente",
            )
        elif response.status_code == HTTP_NOT_FOUND:
            return False, None, response.status_code, "Paciente no encontrado"
        else:
            return (
                False,
                None,
                response.status_code,
                f"Error al obtener paciente: {response.status_code}",
            )
    except requests.RequestException as e:
        return False, None, None, f"Error de conexión con admin_service: {str(e)}"


@citas_bp.route("/citas", methods=["POST"])
@jwt_required()
def crear_cita():
    """Crear una nueva cita médica.

    Returns:
        Tuple[Response, int]: Respuesta JSON con la cita creada y código HTTP.
    """
    usuario_id = get_jwt_identity()

    data = request.get_json()

    # Validación básica de datos requeridos
    if not data or not all(
        k in data for k in ["fecha", "motivo", "id_paciente", "id_doctor", "id_centro"]
    ):
        return jsonify({"error": "Faltan datos requeridos"}), HTTP_BAD_REQUEST

    try:
        # Convertir la fecha a formato datetime
        fecha_dt = datetime.fromisoformat(data["fecha"].replace("Z", "+00:00"))
    except ValueError:
        return jsonify({"error": "Formato de fecha inválido"}), HTTP_BAD_REQUEST

    # Obtener el token del header Authorization
    auth_header = request.headers.get("Authorization")

    # Verificar que el paciente exista y esté activo
    success_paciente, paciente_datos, status_paciente, error_paciente = (
        obtener_datos_paciente(data["id_paciente"], auth_header)
    )
    if not success_paciente:
        if status_paciente == HTTP_UNAUTHORIZED:
            return jsonify(
                {"error": "No autorizado para verificar paciente"}
            ), HTTP_UNAUTHORIZED
        return jsonify(
            {"error": error_paciente or "El paciente no existe"}
        ), HTTP_BAD_REQUEST

    # Verificar que el paciente esté en estado ACTIVO (requisito del enunciado)
    if paciente_datos.get("estado") != "ACTIVO":
        return jsonify({"error": "El paciente no está activo"}), HTTP_BAD_REQUEST

    # Verificar que el doctor exista usando el endpoint /verify
    ok_doctor, resp_doctor = verificar_existencia_user_service(
        f"/verify/doctores/{data['id_doctor']}", auth_header, return_response=True
    )
    if not ok_doctor:
        error_msg = "El doctor no existe"
        if resp_doctor and resp_doctor.status_code == HTTP_UNAUTHORIZED:
            return jsonify(
                {"error": "No autorizado para verificar doctor"}
            ), HTTP_UNAUTHORIZED
        return jsonify({"error": error_msg}), HTTP_BAD_REQUEST

    # Verificar que el centro exista usando el endpoint /verify
    ok_centro, resp_centro = verificar_existencia_user_service(
        f"/verify/centros/{data['id_centro']}", auth_header, return_response=True
    )
    if not ok_centro:
        error_msg = "El centro no existe"
        if resp_centro and resp_centro.status_code == HTTP_UNAUTHORIZED:
            return jsonify(
                {"error": "No autorizado para verificar centro"}
            ), HTTP_UNAUTHORIZED
        return jsonify({"error": error_msg}), HTTP_BAD_REQUEST

    # Verificar que no haya otra cita del doctor en la misma fecha y hora
    cita_conflicto = Appointment.query.filter_by(
        id_doctor=data["id_doctor"],
        fecha=fecha_dt,
        estado=ESTADO_PROGRAMADA,
    ).first()

    if cita_conflicto:
        return jsonify(
            {"error": "El doctor ya tiene una cita programada en esa fecha y hora"}
        ), HTTP_BAD_REQUEST

    # Crear nueva cita
    nueva_cita = Appointment(
        fecha=fecha_dt,
        motivo=data["motivo"],
        id_paciente=data["id_paciente"],
        id_doctor=data["id_doctor"],
        id_centro=data["id_centro"],
        id_usuario_registra=usuario_id,
    )

    db.session.add(nueva_cita)
    db.session.commit()

    return jsonify(
        {
            "mensaje": "Cita creada exitosamente",
            "cita": {
                "id": nueva_cita.id,
                "fecha": nueva_cita.fecha.isoformat(),
                "motivo": nueva_cita.motivo,
                "estado": nueva_cita.estado,
                "id_paciente": nueva_cita.id_paciente,
                "id_doctor": nueva_cita.id_doctor,
                "id_centro": nueva_cita.id_centro,
            },
        }
    ), HTTP_CREATED


@citas_bp.route("/citas", methods=["GET"])
@jwt_required()
def listar_citas():
    """Listar citas con filtros opcionales según el rol del usuario.

    Roles y permisos:
    - Doctor: solo ve sus propias citas (filtrado por id_doctor = su user_id)
    - Secretaria: puede filtrar por fecha
    - Admin: puede filtrar por doctor, centro, fecha, estado, paciente
    - Paciente: solo ve sus propias citas (filtrado por id_paciente = su user_id)

    Returns:
        Tuple[Response, int]: Respuesta JSON con lista de citas y código HTTP.
    """
    # Obtener token del header Authorization
    auth_header = request.headers.get("Authorization")
    token = auth_header.replace("Bearer ", "") if auth_header else ""

    # Verificar usuario y obtener rol
    success_verify, usuario_info, status_verify, error_verify = verificar_usuario(token)
    if not success_verify or not usuario_info or not usuario_info.get("valid"):
        if status_verify == HTTP_UNAUTHORIZED:
            return jsonify(
                {"error": "Token inválido o usuario no encontrado"}
            ), HTTP_UNAUTHORIZED
        return jsonify(
            {"error": error_verify or "Token inválido o usuario no encontrado"}
        ), HTTP_UNAUTHORIZED

    usuario_rol = usuario_info.get("rol")
    usuario_id = usuario_info.get("user_id")

    # Obtener parámetros de consulta
    fecha_inicio = request.args.get("fecha_inicio")
    fecha_fin = request.args.get("fecha_fin")
    id_doctor = request.args.get("id_doctor", type=int)
    id_centro = request.args.get("id_centro", type=int)
    estado = request.args.get("estado")
    id_paciente = request.args.get("id_paciente", type=int)

    # Construir consulta base
    query = Appointment.query

    # Aplicar filtros según el rol del usuario
    if usuario_rol == ROL_MEDICO:
        # Doctor: solo ver sus propias citas
        # NOTA: Asumimos que el user_id coincide con el id_doctor del Doctor
        query = query.filter_by(id_doctor=usuario_id)

    elif usuario_rol == ROL_SECRETARIA:
        # Secretaria: puede filtrar por fecha
        if fecha_inicio:
            query = query.filter(
                Appointment.fecha >= datetime.fromisoformat(fecha_inicio)
            )
        if fecha_fin:
            query = query.filter(Appointment.fecha <= datetime.fromisoformat(fecha_fin))

    elif usuario_rol == ROL_ADMIN:
        # Admin: puede usar todos los filtros disponibles
        if fecha_inicio:
            query = query.filter(
                Appointment.fecha >= datetime.fromisoformat(fecha_inicio)
            )
        if fecha_fin:
            query = query.filter(Appointment.fecha <= datetime.fromisoformat(fecha_fin))
        if id_doctor:
            query = query.filter_by(id_doctor=id_doctor)
        if id_centro:
            query = query.filter_by(id_centro=id_centro)
        if estado:
            query = query.filter_by(estado=estado)
        if id_paciente:
            query = query.filter_by(id_paciente=id_paciente)

    else:
        # Paciente u otros roles: solo ver sus propias citas (por id_paciente)
        query = query.filter_by(id_paciente=usuario_id)

    citas = query.all()

    return jsonify(
        {
            "citas": [
                {
                    "id": c.id,
                    "fecha": c.fecha.isoformat(),
                    "motivo": c.motivo,
                    "estado": c.estado,
                    "id_paciente": c.id_paciente,
                    "id_doctor": c.id_doctor,
                    "id_centro": c.id_centro,
                }
                for c in citas
            ]
        }
    ), HTTP_OK


@citas_bp.route("/citas/<int:cita_id>", methods=["GET"])
@jwt_required()
def obtener_cita(cita_id):
    """Obtener una cita específica por ID.

    Args:
        cita_id: ID de la cita a obtener.

    Returns:
        Tuple[Response, int]: Respuesta JSON con la cita y código HTTP.
    """
    cita = Appointment.query.get(cita_id)

    if not cita:
        return jsonify({"error": "Cita no encontrada"}), HTTP_NOT_FOUND

    return jsonify(
        {
            "cita": {
                "id": cita.id,
                "fecha": cita.fecha.isoformat(),
                "motivo": cita.motivo,
                "estado": cita.estado,
                "id_paciente": cita.id_paciente,
                "id_doctor": cita.id_doctor,
                "id_centro": cita.id_centro,
            }
        }
    ), HTTP_OK


@citas_bp.route("/citas/<int:cita_id>", methods=["PUT"])
@jwt_required()
def cancelar_cita(cita_id):
    """Cancelar una cita existente (Solo roles Admin y Secretaria).

    Args:
        cita_id: ID de la cita a cancelar.

    Returns:
        Tuple[Response, int]: Respuesta JSON con la cita cancelada y código HTTP.
    """
    # Obtener token del header Authorization
    auth_header = request.headers.get("Authorization")
    token = auth_header.replace("Bearer ", "") if auth_header else ""

    # Verificar usuario y obtener rol
    success_verify, usuario_info, status_verify, error_verify = verificar_usuario(token)
    if not success_verify or not usuario_info or not usuario_info.get("valid"):
        if status_verify == HTTP_UNAUTHORIZED:
            return jsonify(
                {"error": "Token inválido o usuario no encontrado"}
            ), HTTP_UNAUTHORIZED
        return jsonify(
            {"error": error_verify or "Token inválido o usuario no encontrado"}
        ), HTTP_UNAUTHORIZED

    usuario_rol = usuario_info.get("rol")

    # Verificar que el usuario tenga rol permitido (Admin o Secretaria)
    if usuario_rol not in [ROL_ADMIN, ROL_SECRETARIA]:
        return jsonify(
            {"error": "No autorizado: solo Admin y Secretaria pueden cancelar citas"}
        ), HTTP_FORBIDDEN

    cita = Appointment.query.get(cita_id)

    if not cita:
        return jsonify({"error": "Cita no encontrada"}), HTTP_NOT_FOUND

    # Verificar que no esté ya cancelada
    if cita.estado == ESTADO_CANCELADA:
        return jsonify({"error": "La cita ya está cancelada"}), HTTP_BAD_REQUEST

    # Cambiar estado a cancelada
    cita.estado = ESTADO_CANCELADA
    db.session.commit()

    return jsonify(
        {
            "mensaje": "Cita cancelada exitosamente",
            "cita": {
                "id": cita.id,
                "fecha": cita.fecha.isoformat(),
                "motivo": cita.motivo,
                "estado": cita.estado,
            },
        }
    ), HTTP_OK


# ENDPOINTS DE HEALTH Y ROOT


@app.route("/health")
def health():
    """Endpoint de verificación de salud del servicio.

    Returns:
        Tuple[Response, int]: Respuesta JSON con estado del servicio y código HTTP.
    """
    return jsonify(
        {"service": "citas_service", "status": "ok", "environment": "development"}
    ), HTTP_OK


@app.route("/")
def root():
    """Endpoint raíz con información del servicio.

    Returns:
        Tuple[Response, int]: Respuesta JSON con información del servicio y código HTTP.
    """
    return jsonify(
        {
            "name": "OdontoCare - Servicio de Gestión de Citas",
            "version": "1.0.0",
            "endpoints": {"citas": "/citas", "health": "/health"},
        }
    ), HTTP_OK


# INICIALIZACIÓN

# Registrar blueprint
app.register_blueprint(citas_bp)

# Crear tablas de la base de datos
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, debug=True)
