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
# BASE DE DATOS SIMULADA / SIMULACIÓN ORM SQL
# -------------------------------------------------------------------
# En producción se conecta vía SQLAlchemy con aquaalert_db
db_banos = {
    1: {"id": 1, "codigo_qr": "EDIF-D-PB-H", "edificio": "Edificio D - Sistemas", "planta": "Planta Baja", "genero": "Hombres", "estado_actual": "Operativo", "posicion_x": 460, "posicion_y": 420},
    2: {"id": 2, "codigo_qr": "EDIF-D-PB-M", "edificio": "Edificio D - Sistemas", "planta": "Planta Baja", "genero": "Mujeres", "estado_actual": "Operativo", "posicion_x": 460, "posicion_y": 420},
    3: {"id": 3, "codigo_qr": "EDIF-C-PB-H", "edificio": "Edificio C - Cómputo", "planta": "Planta Baja", "genero": "Hombres", "estado_actual": "Operativo", "posicion_x": 450, "posicion_y": 520},
    4: {"id": 4, "codigo_qr": "EDIF-H-PB-H", "edificio": "Edificio H - Industrial", "planta": "Planta Baja", "genero": "Hombres", "estado_actual": "Fuera de Servicio", "posicion_x": 380, "posicion_y": 550},
}

db_reportes = []

# -------------------------------------------------------------------
# CLASE 1 Y 2 UML: LÓGICA Y ALGORITMO DEL SEMÁFORO AUTOMÁTICO
# -------------------------------------------------------------------
def evaluar_algoritmo_semaforo(bano_id: int):
    """
    Evalúa la frecuencia y gravedad de reportes en los últimos 15 minutos:
    - 🟢 Verde (Operativo): 0 reportes de falla o reporte 'Limpio y funcionando'.
    - 🟡 Amarillo (Parcial): 1 reporte de falla parcial ('Sin agua en lavamanos' / 'Baños Sucios').
    - 🔴 Rojo (Fuera de Servicio): >= 2 reportes negativos O 1 falla crítica ('Sin agua en inodoros' / 'Fuga activa' / 'Baños Sucios').
    """
    ahora = datetime.now()
    hace_15_min = ahora - timedelta(minutes=15)
    
    # Filtrar reportes recientes para este baño
    reportes_recientes = [
        r for r in db_reportes 
        if r["bano_id"] == bano_id and r["fecha_hora"] >= hace_15_min and r["estado_reporte"] == "Pendiente"
    ]
    
    if not reportes_recientes:
        return
    
    # Contar tipos de incidencias
    fallas_criticas = sum(1 for r in reportes_recientes if r["tipo_incidencia"] in ["Sin agua en inodoros", "Fuga activa"])
    fallas_parciales = sum(1 for r in reportes_recientes if r["tipo_incidencia"] in ["Sin agua en lavamanos", "Baños Sucios"])
    reportes_positivos = sum(1 for r in reportes_recientes if r["tipo_incidencia"] == "Limpio y funcionando")
    
    bano = db_banos.get(bano_id)
    if not bano:
        return

    # Reglas de negocio del semáforo
    if reportes_positivos > 0 and fallas_criticas == 0 and fallas_parciales == 0:
        bano["estado_actual"] = "Operativo"  # 🟢 Verde
    elif fallas_criticas >= 1 or (fallas_parciales + fallas_criticas) >= 2:
        bano["estado_actual"] = "Fuera de Servicio"  # 🔴 Rojo
    elif fallas_parciales == 1:
        bano["estado_actual"] = "Parcial"  # 🟡 Amarillo

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
    resultado = []
    for b in db_banos.values():
        resultado.append(ModuloSanitarioDTO(
            id=b["id"],
            codigo_qr=b["codigo_qr"],
            edificio=b["edificio"],
            planta=b["planta"],
            genero=b["genero"],
            estado_semaforo=b["estado_actual"],
            posicion_x=b["posicion_x"],
            posicion_y=b["posicion_y"]
        ))
    return resultado

@app.get("/api/modulos/{codigo_qr}")
def consultar_modulo_por_qr(codigo_qr: str):
    """CLASE 1 (ModuloSanitario): Precarga la información al escanear el código QR."""
    for b in db_banos.values():
        if b["codigo_qr"] == codigo_qr:
            return b
    raise HTTPException(status_code=404, detail="Módulo sanitario no encontrado")

@app.post("/api/reportes", status_code=status.HTTP_201_CREATED)
def crear_reporte(datos: ReporteCrearDTO, request: Request):
    """CLASE 2 (ReporteIncidencia): Registra reporte anónimo previa validación de seguridad."""
    ip_cliente = request.client.host
    
    # 1. Validar Anti-Spam (Rate limiting)
    if not ValidadorSeguridad.validar_rate_limiting(ip_cliente, datos.bano_id):
        raise HTTPException(
            status_code=429, 
            detail="Ha enviado un reporte recientemente. Por favor espere 15 minutos."
        )
    
    # 2. Sanitizar Comentario (Seguridad XSS/SQLi)
    comentario_seguro = ValidadorSeguridad.sanitizar_texto(datos.comentario or "")
    
    # 3. Guardar Reporte
    nuevo_reporte = {
        "id": len(db_reportes) + 1,
        "bano_id": datos.bano_id,
        "tipo_incidencia": datos.tipo_incidencia,
        "comentario": comentario_seguro,
        "fecha_hora": datetime.now(),
        "estado_reporte": "Pendiente",
        "ip_hash": hash(ip_cliente)
    }
    db_reportes.append(nuevo_reporte)
    
    # 4. Ejecutar Algoritmo del Semáforo
    evaluar_algoritmo_semaforo(datos.bano_id)
    
    return {
        "mensaje": "Reporte registrado correctamente",
        "nuevo_estado": db_banos[datos.bano_id]["estado_actual"]
    }

@app.put("/api/admin/incidencias/{bano_id}/resolver")
def resolver_incidencia_admin(bano_id: int):
    """CLASE 3 (UsuarioAdministrador): Mantenimiento restablece el módulo a Verde (Operativo)."""
    if bano_id not in db_banos:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    
    # Restablecer a Verde
    db_banos[bano_id]["estado_actual"] = "Operativo"
    
    # Marcar reportes como resueltos
    for r in db_reportes:
        if r["bano_id"] == bano_id:
            r["estado_reporte"] = "Resuelto"
            
    return {"mensaje": f"Módulo {bano_id} restablecido a Verde (Operativo)"}

if __name__ == "__main__":
    puerto = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=puerto)