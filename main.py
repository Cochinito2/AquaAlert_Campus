from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timedelta
import html
import re
import os
import uvicorn
import pymysql

app = FastAPI(
    title="AquaAlert_Campus API",
    description="Backend para monitoreo sanitario y enrutamiento en tiempo real",
    version="1.0.0"
)

# Permitir peticiones desde la PWA móvil y el mapa interactivo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# CONEXIÓN A BASE DE DATOS (LAYERBASE / MARIADB)
# -------------------------------------------------------------------
def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "aquaalert-campus-dove-plank.sage.cloud.layerbase.dev"),
        port=int(os.getenv("DB_PORT", 48283)),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", "ev0VE1I5BBqyxmScSWxL09y9"),
        database=os.getenv("DB_NAME", "aquaalert_campus"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        ssl={"ssl": {}}
    )

# -------------------------------------------------------------------
# CLASE 5 UML: ValidadorSeguridad (Control Anti-Spam y Sanitización)
# -------------------------------------------------------------------
class ValidadorSeguridad:
    # Memoria temporal para Rate Limiting (IP / Hash -> Último reporte)
    registro_envios = {}

    @classmethod
    def sanitizar_texto(cls, entrada: str, max_caracteres: int = 255) -> str:
        """Inhibe inyecciones XSS / SQLi y recorta el texto."""
        if not entrada:
            return ""
        # Limpiar espacios extra y recortar a max_caracteres
        texto_limpio = entrada.strip()[:max_caracteres]
        # Escapar caracteres HTML especiales (<, >, &, ", ')
        return html.escape(texto_limpio)

    @classmethod
    def validar_rate_limiting(cls, ip_cliente: str, bano_id: int, limite_minutos: int = 15) -> bool:
        """Permite máximo 1 reporte cada 15 minutos por usuario/baño."""
        clave = f"{ip_cliente}_{bano_id}"
        ahora = datetime.now()
        
        if clave in cls.registro_envios:
            ultimo_envio = cls.registro_envios[clave]
            if ahora - ultimo_envio < timedelta(minutes=limite_minutos):
                return False  # Bloqueado por spam
        
        cls.registro_envios[clave] = ahora
        return True

# -------------------------------------------------------------------
# MODELOS DE DATOS (Pydantic / DTOs)
# -------------------------------------------------------------------
class ReporteCrearDTO(BaseModel):
    bano_id: int
    tipo_incidencia: str = Field(..., description="Sin agua en lavamanos | Sin agua en inodoros | Fuga activa | Baños Sucios | Limpio y funcionando")
    comentario: Optional[str] = Field(None, max_length=255)

class ModuloSanitarioDTO(BaseModel):
    id: int
    codigo_qr: str
    edificio: str
    planta: str
    genero: str
    estado_semaforo: str
    posicion_x: int
    posicion_y: int

# -------------------------------------------------------------------
# CLASE 1 Y 2 UML: LÓGICA Y ALGORITMO DEL SEMÁFORO AUTOMÁTICO
# -------------------------------------------------------------------
def evaluar_algoritmo_semaforo(bano_id: int, cursor) -> str:
    """
    Evalúa la frecuencia y gravedad de reportes en los últimos 15 minutos:
    - 🟢 Verde (Operativo): 0 reportes de falla o reporte 'Limpio y funcionando'.
    - 🟡 Amarillo (Parcial): 1 reporte de falla parcial ('Sin agua en lavamanos' / 'Baños Sucios').
    - 🔴 Rojo (Fuera de Servicio): >= 2 reportes negativos O 1 falla crítica ('Sin agua en inodoros' / 'Fuga activa' / 'Baños Sucios').
    """
    ahora = datetime.now()
    hace_15_min = ahora - timedelta(minutes=15)
    
    # Filtrar reportes recientes para este baño en la base de datos
    cursor.execute(
        """
        SELECT tipo_incidencia FROM reportes 
        WHERE bano_id = %s AND fecha_hora >= %s AND estado_reporte = 'Pendiente'
        """,
        (bano_id, hace_15_min)
    )
    reportes_recientes = cursor.fetchall()

    cursor.execute("SELECT estado_actual FROM banos WHERE id = %s", (bano_id,))
    bano = cursor.fetchone()
    if not bano:
        return "Operativo"

    nuevo_estado = bano["estado_actual"]

    if not reportes_recientes:
        return nuevo_estado
    
    # Contar tipos de incidencias
    fallas_criticas = sum(1 for r in reportes_recientes if r["tipo_incidencia"] in ["Sin agua en inodoros", "Fuga activa"])
    fallas_parciales = sum(1 for r in reportes_recientes if r["tipo_incidencia"] in ["Sin agua en lavamanos", "Baños Sucios"])
    reportes_positivos = sum(1 for r in reportes_recientes if r["tipo_incidencia"] == "Limpio y funcionando")

    # Reglas de negocio del semáforo
    if reportes_positivos > 0 and fallas_criticas == 0 and fallas_parciales == 0:
        nuevo_estado = "Operativo"  # 🟢 Verde
    elif fallas_criticas >= 1 or (fallas_parciales + fallas_criticas) >= 2:
        nuevo_estado = "Fuera de Servicio"  # 🔴 Rojo
    elif fallas_parciales == 1:
        nuevo_estado = "Parcial"  # 🟡 Amarillo

    cursor.execute(
        "UPDATE banos SET estado_actual = %s WHERE id = %s",
        (nuevo_estado, bano_id)
    )
    return nuevo_estado

# -------------------------------------------------------------------
# ENDPOINTS REST (API PUBLIC & ADMIN)
# -------------------------------------------------------------------

@app.get("/")
def servir_interfaz():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"status": "AquaAlert_Campus API activa"}

@app.get("/api/mapa/estatus", response_model=List[ModuloSanitarioDTO])
def obtener_estatus_global():
    """CLASE 4 (MapaInteractivo): Retorna el estado del semáforo y coordenadas de todos los módulos."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT b.id, b.codigo_qr, e.nombre AS edificio, b.planta, 
                       b.genero, b.estado_actual AS estado_semaforo, 
                       e.posicion_x, e.posicion_y
                FROM banos b
                INNER JOIN edificios e ON b.edificio_id = e.id
                ORDER BY b.id ASC
            """)
            return cursor.fetchall()
    finally:
        conn.close()

@app.get("/api/modulos/{codigo_qr}")
def consultar_modulo_por_qr(codigo_qr: str):
    """CLASE 1 (ModuloSanitario): Precarga la información al escanear el código QR."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT b.*, e.nombre AS edificio, e.posicion_x, e.posicion_y
                FROM banos b
                INNER JOIN edificios e ON b.edificio_id = e.id
                WHERE b.codigo_qr = %s
            """, (codigo_qr,))
            bano = cursor.fetchone()
            if not bano:
                raise HTTPException(status_code=404, detail="Módulo sanitario no encontrado")
            return bano
    finally:
        conn.close()

@app.post("/api/reportes", status_code=status.HTTP_201_CREATED)
def crear_reporte(datos: ReporteCrearDTO, request: Request):
    """CLASE 2 (ReporteIncidencia): Registra reporte anónimo previa validación de seguridad."""
    ip_cliente = request.client.host if request.client else "0.0.0.0"
    
    # 1. Validar Anti-Spam (Rate limiting)
    if not ValidadorSeguridad.validar_rate_limiting(ip_cliente, datos.bano_id):
        raise HTTPException(
            status_code=429, 
            detail="Ha enviado un reporte recientemente. Por favor espere 15 minutos."
        )
    
    # 2. Sanitizar Comentario (Seguridad XSS/SQLi)
    comentario_seguro = ValidadorSeguridad.sanitizar_texto(datos.comentario or "")
    ip_hash = str(abs(hash(ip_cliente)))
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM banos WHERE id = %s", (datos.bano_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Baño no encontrado")

            # 3. Guardar Reporte en MySQL/MariaDB
            cursor.execute("""
                INSERT INTO reportes (bano_id, tipo_incidencia, comentario, estado_reporte, ip_hash)
                VALUES (%s, %s, %s, 'Pendiente', %s)
            """, (datos.bano_id, datos.tipo_incidencia, comentario_seguro, ip_hash))

            # 4. Ejecutar Algoritmo del Semáforo
            nuevo_estado = evaluar_algoritmo_semaforo(datos.bano_id, cursor)
        conn.commit()

        return {
            "mensaje": "Reporte registrado correctamente",
            "nuevo_estado": nuevo_estado
        }
    finally:
        conn.close()

@app.put("/api/admin/incidencias/{bano_id}/resolver")
def resolver_incidencia_admin(bano_id: int):
    """CLASE 3 (UsuarioAdministrador): Mantenimiento restablece el módulo a Verde (Operativo)."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM banos WHERE id = %s", (bano_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Módulo no encontrado")
            
            # Restablecer a Verde
            cursor.execute("UPDATE banos SET estado_actual = 'Operativo' WHERE id = %s", (bano_id,))
            
            # Marcar reportes como resueltos
            cursor.execute("UPDATE reportes SET estado_reporte = 'Resuelto' WHERE bano_id = %s", (bano_id,))
        conn.commit()
            
        return {"mensaje": f"Módulo {bano_id} restablecido a Verde (Operativo)"}
    finally:
        conn.close()

if __name__ == "__main__":
    puerto = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=puerto)
