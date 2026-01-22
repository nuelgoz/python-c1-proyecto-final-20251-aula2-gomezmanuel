#!/usr/bin/env python3
"""
OdontoCare - Cliente HTTP REST

Cliente HTTP para interactuar con la API de OdontoCare.
Menús profesionales para acceder a todos los endpoints.
Carga masiva desde CSV (uno por uno).
"""

import csv
import json
import sys

import requests

# Configuración
ADMIN_URL = "http://localhost:8000"
CITAS_URL = "http://localhost:8001"
TOKEN = None

# Códigos de estado
HTTP_OK = 200
HTTP_CREATED = 201


def imprimir_json(datos, titulo=""):
    """Imprime datos en formato JSON"""
    if titulo:
        print(f"\n{titulo}:")
    print(json.dumps(datos, indent=2, ensure_ascii=False))


def leer_csv(ruta):
    """Lee archivo CSV y retorna lista de diccionarios"""
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return [row for row in reader]
    except FileNotFoundError:
        print(f"Error: No existe el archivo {ruta}")
        sys.exit(1)
    except Exception as e:
        print(f"Error leyendo CSV: {e}")
        sys.exit(1)


def enviar_peticion(metodo, url, datos=None):
    """Envía petición HTTP y muestra REQUEST/RESPONSE"""
    headers = {"Content-Type": "application/json"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"

    print(f"\n  📤 {metodo.upper()} {url}")

    if datos:
        imprimir_json(datos, "  📋 REQUEST")

    print(f"  ⏳ ENVIANDO...")

    try:
        if metodo == "GET":
            response = requests.get(url, headers=headers, timeout=5)
        elif metodo == "POST":
            response = requests.post(url, json=datos, headers=headers, timeout=5)
        elif metodo == "PUT":
            response = requests.put(url, json=datos, headers=headers, timeout=5)
        elif metodo == "DELETE":
            response = requests.delete(url, headers=headers, timeout=5)
        else:
            print(f"Error: Método no soportado: {metodo}")
            return None
    except requests.exceptions.ConnectionError:
        print(f"\n❌ Error de conexión")
        print(f"   No se puede conectar a: {url}")
        print(f"   Ejecuta: docker-compose up")
        return None
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return None

    print(f"  📥 RESPONSE: {response.status_code}")

    try:
        response_json = response.json()
        imprimir_json(response_json, "  📬 RESPONSE")
        return response_json
    except:
        print(response.text)
        return None


# ========================================
# MENÚS
# ========================================


def menu_autenticacion():
    """Menú de autenticación"""
    global TOKEN

    while True:
        print("\n" + "═" * 70)
        print("║           🔐  AUTENTICACIÓN           ║")
        print("═" * 70)
        print("1. Registrar usuario (POST /auth/register)")
        print("2. Iniciar sesión (POST /auth/login)")
        print("3. Verificar token (GET /auth/verify)")
        print("0. Volver")

        opcion = input("\nOpción: ").strip()

        if opcion == "0":
            break
        elif opcion == "1":
            username = input("Username: ")
            password = input("Password: ")
            rol = input("Rol (admin/medico/secretaria/paciente): ") or "paciente"
            datos = {"username": username, "password": password, "rol": rol}
            enviar_peticion("POST", f"{ADMIN_URL}/auth/register", datos)
        elif opcion == "2":
            username = input("Username: ")
            password = input("Password: ")
            datos = {"username": username, "password": password}
            resultado = enviar_peticion("POST", f"{ADMIN_URL}/auth/login", datos)
            if resultado and resultado.get("access_token"):
                TOKEN = resultado["access_token"]
                print(f"\n✅ Token guardado: {TOKEN[:20]}...")
        elif opcion == "3":
            if TOKEN:
                enviar_peticion("GET", f"{ADMIN_URL}/auth/verify")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")


def menu_pacientes():
    """Menú de pacientes"""
    while True:
        print("\n" + "─" * 70)
        print("  👤 PACIENTES")
        print("─" * 70)
        print("1. Listar todos (GET /admin/pacientes)")
        print("2. Obtener por ID (GET /admin/pacientes/{id})")
        print("3. Crear (POST /admin/pacientes)")
        print("4. Actualizar (PUT /admin/pacientes/{id})")
        print("5. Eliminar (DELETE /admin/pacientes/{id})")
        print("6. Cargar desde CSV")
        print("0. Volver")

        opcion = input("\nOpción: ").strip()

        if opcion == "0":
            break
        elif opcion == "1":
            if TOKEN:
                enviar_peticion("GET", f"{ADMIN_URL}/admin/pacientes")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "2":
            paciente_id = input("ID del paciente: ")
            if TOKEN:
                enviar_peticion("GET", f"{ADMIN_URL}/admin/pacientes/{paciente_id}")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "3":
            nombre = input("Nombre: ")
            telefono = input("Teléfono: ")
            datos = {"nombre": nombre}
            if telefono:
                datos["telefono"] = telefono
            if TOKEN:
                enviar_peticion("POST", f"{ADMIN_URL}/admin/pacientes", datos)
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "4":
            paciente_id = input("ID del paciente: ")
            nombre = input("Nombre: ")
            telefono = input("Teléfono: ")
            estado = input("Estado (ACTIVO/INACTIVO): ")
            datos = {"nombre": nombre}
            if telefono:
                datos["telefono"] = telefono
            if estado:
                datos["estado"] = estado
            if TOKEN:
                enviar_peticion(
                    "PUT", f"{ADMIN_URL}/admin/pacientes/{paciente_id}", datos
                )
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "5":
            paciente_id = input("ID del paciente: ")
            if TOKEN:
                enviar_peticion("DELETE", f"{ADMIN_URL}/admin/pacientes/{paciente_id}")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "6":
            csv_path = (
                input(f"Ruta del archivo [data/pacientes.csv]: ")
                or "data/pacientes.csv"
            )
            cargar_pacientes_csv(csv_path)


def menu_doctores():
    """Menú de doctores"""
    while True:
        print("\n" + "─" * 70)
        print("  👨‍⚕️  DOCTORES")
        print("─" * 70)
        print("1. Listar todos (GET /admin/doctores)")
        print("2. Obtener por ID (GET /admin/doctores/{id})")
        print("3. Crear (POST /admin/doctores)")
        print("4. Actualizar (PUT /admin/doctores/{id})")
        print("5. Eliminar (DELETE /admin/doctores/{id})")
        print("6. Cargar desde CSV")
        print("0. Volver")

        opcion = input("\nOpción: ").strip()

        if opcion == "0":
            break
        elif opcion == "1":
            if TOKEN:
                enviar_peticion("GET", f"{ADMIN_URL}/admin/doctores")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "2":
            doctor_id = input("ID del doctor: ")
            if TOKEN:
                enviar_peticion("GET", f"{ADMIN_URL}/admin/doctores/{doctor_id}")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "3":
            nombre = input("Nombre: ")
            especialidad = input("Especialidad: ")
            datos = {"nombre": nombre, "especialidad": especialidad}
            if TOKEN:
                enviar_peticion("POST", f"{ADMIN_URL}/admin/doctores", datos)
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "4":
            doctor_id = input("ID del doctor: ")
            nombre = input("Nombre: ")
            especialidad = input("Especialidad: ")
            datos = {"nombre": nombre, "especialidad": especialidad}
            if TOKEN:
                enviar_peticion("PUT", f"{ADMIN_URL}/admin/doctores/{doctor_id}", datos)
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "5":
            doctor_id = input("ID del doctor: ")
            if TOKEN:
                enviar_peticion("DELETE", f"{ADMIN_URL}/admin/doctores/{doctor_id}")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "6":
            csv_path = (
                input(f"Ruta del archivo [data/doctores.csv]: ") or "data/doctores.csv"
            )
            cargar_doctores_csv(csv_path)


def menu_centros():
    """Menú de centros"""
    while True:
        print("\n" + "─" * 70)
        print("  🏥  CENTROS")
        print("─" * 70)
        print("1. Listar todos (GET /admin/centros)")
        print("2. Obtener por ID (GET /admin/centros/{id})")
        print("3. Crear (POST /admin/centros)")
        print("4. Actualizar (PUT /admin/centros/{id})")
        print("5. Eliminar (DELETE /admin/centros/{id})")
        print("6. Cargar desde CSV")
        print("0. Volver")

        opcion = input("\nOpción: ").strip()

        if opcion == "0":
            break
        elif opcion == "1":
            if TOKEN:
                enviar_peticion("GET", f"{ADMIN_URL}/admin/centros")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "2":
            centro_id = input("ID del centro: ")
            if TOKEN:
                enviar_peticion("GET", f"{ADMIN_URL}/admin/centros/{centro_id}")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "3":
            nombre = input("Nombre: ")
            direccion = input("Dirección: ")
            datos = {"nombre": nombre, "direccion": direccion}
            if TOKEN:
                enviar_peticion("POST", f"{ADMIN_URL}/admin/centros", datos)
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "4":
            centro_id = input("ID del centro: ")
            nombre = input("Nombre: ")
            direccion = input("Dirección: ")
            datos = {"nombre": nombre, "direccion": direccion}
            if TOKEN:
                enviar_peticion("PUT", f"{ADMIN_URL}/admin/centros/{centro_id}", datos)
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "5":
            centro_id = input("ID del centro: ")
            if TOKEN:
                enviar_peticion("DELETE", f"{ADMIN_URL}/admin/centros/{centro_id}")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "6":
            csv_path = (
                input(f"Ruta del archivo [data/centros.csv]: ") or "data/centros.csv"
            )
            cargar_centros_csv(csv_path)


def menu_citas():
    """Menú de citas"""
    while True:
        print("\n" + "─" * 70)
        print("  📅  CITAS")
        print("─" * 70)
        print("1. Listar todas (GET /citas)")
        print("2. Obtener por ID (GET /citas/{id})")
        print("3. Crear (POST /citas)")
        print("4. Cancelar (PUT /citas/{id})")
        print("6. Cargar desde CSV")
        print("0. Volver")

        opcion = input("\nOpción: ").strip()

        if opcion == "0":
            break
        elif opcion == "1":
            if TOKEN:
                enviar_peticion("GET", f"{CITAS_URL}/citas")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "2":
            cita_id = input("ID de la cita: ")
            if TOKEN:
                enviar_peticion("GET", f"{CITAS_URL}/citas/{cita_id}")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "3":
            id_paciente = input("ID del paciente: ")
            id_doctor = input("ID del doctor: ")
            id_centro = input("ID del centro: ")
            motivo = input("Motivo: ")
            fecha = input("Fecha (YYYY-MM-DD HH:MM:SS): ")
            datos = {
                "id_paciente": int(id_paciente),
                "id_doctor": int(id_doctor),
                "id_centro": int(id_centro),
                "motivo": motivo,
                "fecha": fecha,
            }
            if TOKEN:
                enviar_peticion("POST", f"{CITAS_URL}/citas", datos)
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "4":
            cita_id = input("ID de la cita: ")
            if TOKEN:
                enviar_peticion("PUT", f"{CITAS_URL}/citas/{cita_id}")
            else:
                print("❌ Error: Debes iniciar sesión primero")
                print("   Selecciona opción 2 para iniciar sesión")
        elif opcion == "6":
            csv_path = input(f"Ruta del archivo [data/citas.csv]: ") or "data/citas.csv"
            cargar_citas_csv(csv_path)


def menu_admin():
    """Menú de admin service"""
    while True:
        print("\n" + "─" * 70)
        print("  🏥  ADMIN SERVICE")
        print("─" * 70)
        print("1. Pacientes")
        print("2. Doctores")
        print("3. Centros")
        print("0. Volver")

        opcion = input("\nOpción: ").strip()

        if opcion == "0":
            break
        elif opcion == "1":
            menu_pacientes()
        elif opcion == "2":
            menu_doctores()
        elif opcion == "3":
            menu_centros()


def menu_principal():
    """Menú principal"""
    while True:
        print("\n" + "─" * 70)
        print("  🏥 ODONTOCARE - CLIENTE HTTP REST")
        print(f"  Token: {'✅ Activo' if TOKEN else '❌ No autenticado'}")
        print("─" * 70)
        print("  📋 SERVICIOS")
        print("─" * 70)
        print("  1. 🔐  Autenticación")
        print("  2. 🏥  Admin Service")
        print("  3. 📅  Citas Service")
        print("  4. 📂  Cargar desde CSV")
        print("  0. 🚪  Salir")
        print("─" * 70)

        opcion = input("\nOpción: ").strip()

        if opcion == "0":
            print("\n¡Hasta pronto!")
            sys.exit(0)
        elif opcion == "1":
            menu_autenticacion()
        elif opcion == "2":
            menu_admin()
        elif opcion == "3":
            menu_citas()
        elif opcion == "4":
            menu_carga_csv()


# ========================================
# CARGA DESDE CSV
# ========================================


def menu_carga_csv():
    """Menú para cargar CSV"""
    while True:
        print("\n" + "─" * 70)
        print("  📂  CARGAR DESDE CSV")
        print("─" * 70)
        print("1. Pacientes")
        print("2. Doctores")
        print("3. Centros")
        print("4. Citas")
        print("5. Usuarios")
        print("0. Volver")

        opcion = input("\nOpción: ").strip()

        if opcion == "0":
            break
        elif opcion == "1":
            csv_path = (
                input(f"Ruta del archivo [data/pacientes.csv]: ")
                or "data/pacientes.csv"
            )
            cargar_pacientes_csv(csv_path)
        elif opcion == "2":
            csv_path = (
                input(f"Ruta del archivo [data/doctores.csv]: ") or "data/doctores.csv"
            )
            cargar_doctores_csv(csv_path)
        elif opcion == "3":
            csv_path = (
                input(f"Ruta del archivo [data/centros.csv]: ") or "data/centros.csv"
            )
            cargar_centros_csv(csv_path)
        elif opcion == "4":
            csv_path = input(f"Ruta del archivo [data/citas.csv]: ") or "data/citas.csv"
            cargar_citas_csv(csv_path)
        elif opcion == "5":
            csv_path = (
                input(f"Ruta del archivo [data/usuarios.csv]: ") or "data/usuarios.csv"
            )
            cargar_usuarios_csv(csv_path)


def cargar_pacientes_csv(csv_path):
    """Carga pacientes desde CSV uno por uno"""
    datos_csv = leer_csv(csv_path)
    url = f"{ADMIN_URL}/admin/pacientes"

    print(f"\n📥 Cargando {len(datos_csv)} pacientes...")

    for i, fila in enumerate(datos_csv, 1):
        datos = {"nombre": fila.get("nombre")}
        if fila.get("telefono"):
            datos["telefono"] = fila.get("telefono")
        if fila.get("estado"):
            datos["estado"] = fila.get("estado")

        print(f"\n{'─' * 70}")
        print(f"Registro {i}/{len(datos_csv)} de {len(datos_csv)}")
        enviar_peticion("POST", url, datos)


def cargar_doctores_csv(csv_path):
    """Carga doctores desde CSV uno por uno"""
    datos_csv = leer_csv(csv_path)
    url = f"{ADMIN_URL}/admin/doctores"

    print(f"\n📥 Cargando {len(datos_csv)} doctores...")

    for i, fila in enumerate(datos_csv, 1):
        datos = {
            "nombre": fila.get("nombre"),
            "especialidad": fila.get("especialidad", ""),
        }
        if fila.get("telefono"):
            datos["telefono"] = fila.get("telefono")
        if fila.get("estado"):
            datos["estado"] = fila.get("estado")

        print(f"\n{'─' * 70}")
        print(f"Registro {i}/{len(datos_csv)} de {len(datos_csv)}")
        enviar_peticion("POST", url, datos)


def cargar_centros_csv(csv_path):
    """Carga centros desde CSV uno por uno"""
    datos_csv = leer_csv(csv_path)
    url = f"{ADMIN_URL}/admin/centros"

    print(f"\n📥 Cargando {len(datos_csv)} centros...")

    for i, fila in enumerate(datos_csv, 1):
        datos = {"nombre": fila.get("nombre"), "direccion": fila.get("direccion", "")}
        if fila.get("telefono"):
            datos["telefono"] = fila.get("telefono")
        if fila.get("estado"):
            datos["estado"] = fila.get("estado")

        print(f"\n{'─' * 70}")
        print(f"Registro {i}/{len(datos_csv)} de {len(datos_csv)}")
        enviar_peticion("POST", url, datos)


def cargar_usuarios_csv(csv_path):
    """Carga usuarios desde CSV uno por uno"""
    datos_csv = leer_csv(csv_path)
    url = f"{ADMIN_URL}/auth/register"

    print(f"\n📥 Cargando {len(datos_csv)} usuarios...")

    for i, fila in enumerate(datos_csv, 1):
        datos = {
            "username": fila.get("username"),
            "password": fila.get("password"),
            "rol": fila.get("rol", "paciente"),
        }

        print(f"\n{'─' * 70}")
        print(f"Registro {i}/{len(datos_csv)} de {len(datos_csv)}")
        enviar_peticion("POST", url, datos)


def cargar_citas_csv(csv_path):
    """Carga citas desde CSV uno por uno"""
    datos_csv = leer_csv(csv_path)
    url = f"{CITAS_URL}/citas"

    print(f"\n📥 Cargando {len(datos_csv)} citas...")

    for i, fila in enumerate(datos_csv, 1):
        datos = {
            "fecha": fila.get("fecha"),
            "motivo": fila.get("motivo"),
            "id_paciente": int(fila.get("id_paciente")),
            "id_doctor": int(fila.get("id_doctor")),
            "id_centro": int(fila.get("id_centro")),
        }
        if fila.get("estado"):
            datos["estado"] = fila.get("estado")

        print(f"\n{'─' * 70}")
        print(f"Registro {i}/{len(datos_csv)} de {len(datos_csv)}")
        enviar_peticion("POST", url, datos)


def main():
    """Función principal"""
    menu_principal()


if __name__ == "__main__":
    main()
