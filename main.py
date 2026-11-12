from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timedelta
import html

app = FastAPI(
    title="AquaAlert_Campus API",
    description="Backend para monitoreo sanitario y enrutamiento en tiempo real",
    version="1.0.0"
)

# Configuración CORS para permitir peticiones del cliente web
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Seguridad y Autenticación de Administrador
security = HTTPBearer()
tokens_admin_activos = set()

# -------------------------------------------------------------------
# CLASE 5 UML: ValidadorSeguridad (Control Anti-Spam y Sanitización)
# -------------------------------------------------------------------
class ValidadorSeguridad:
    registro_envios = {}

    @classmethod
    def sanitizar_texto(cls, entrada: str, max_caracteres: int = 255) -> str:
        """Inhibe inyecciones XSS / SQLi y recorta el texto."""
        if not entrada:
            return ""
        texto_limpio = entrada.strip()[:max_caracteres]
        return html.escape(texto_limpio)

    @classmethod
    def validar_rate_limiting(cls, ip_cliente: str, bano_id: int, limite_minutos: int = 15) -> bool:
        """Permite máximo 1 reporte cada 15 minutos por usuario/baño."""
        clave = f"{ip_cliente}_{bano_id}"
        ahora = datetime.now()
        
        if clave in cls.registro_envios:
            ultimo_envio = cls.registro_envios[clave]
            if ahora - ultimo_envio < timedelta(minutes=limite_minutos):
                return False
        
        cls.registro_envios[clave] = ahora
        return True

# -------------------------------------------------------------------
# MODELOS DE DATOS (Pydantic / DTOs)
# -------------------------------------------------------------------
from fastapi import FastAPI, HTTPException, Request, Depends, status, Header

class LoginAdminDTO(BaseModel):
    username: str
    password: str

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
# BASE DE DATOS SIMULADA / ORM SQL
# -------------------------------------------------------------------
edificios_seed = [
    ("Edificio A - Dirección y Servicios", "EDIF-A", 580, 550),
    ("Edificio B - Estudios Profesionales", "EDIF-B", 500, 480),
    ("Edificio C - Centro de Cómputo", "EDIF-C", 450, 390),
    ("Edificio D - Sistemas y Computación", "EDIF-D", 420, 290),
    ("Edificio E - Posgrado e Investigación", "EDIF-E", 300, 120),
    ("Edificio F - Aulas", "EDIF-F", 400, 340),
    ("Edificio G - Aulas", "EDIF-G", 360, 380),
    ("Edificio H - Ingeniería Industrial", "EDIF-H", 370, 440),
    ("Edificio I - Centro de Información", "EDIF-I", 320, 580),
    ("Edificio J - Cafetería", "EDIF-J", 280, 480),
    ("Edificio K - Recursos Materiales", "EDIF-K", 260, 340),
    ("Edificio L - Desarrollo Académico", "EDIF-L", 220, 320),
    ("Edificio M - Metal Mecánica", "EDIF-M", 180, 220),
    ("Edificio N - Ciencias Básicas", "EDIF-N", 240, 280),
    ("Edificio Ñ - Servicio Médico", "EDIF-Ñ", 180, 360),
    ("Edificio O - Aulas", "EDIF-O", 220, 420),
    ("Edificio P - Lab. Química", "EDIF-P", 200, 480),
    ("Edificio Q - Ciencias Económicas", "EDIF-Q", 180, 540),
    ("Edificio R - Aulas", "EDIF-R", 140, 480),
    ("Edificio S - Planta Piloto", "EDIF-S", 110, 420),
    ("Edificio T - Electromecánica", "EDIF-T", 110, 340),
    ("Edificio W - Auditorio y Gimnasio", "EDIF-W", 740, 200),
    ("Edificio Y - Aula Magna", "EDIF-Y", 440, 640),
    ("Edificio Z - Vinculación", "EDIF-Z", 340, 640),
]

db_banos = {}
_id = 1
for nombre, codigo, x, y in edificios_seed:
    db_banos[_id] = {
        "id": _id,
        "codigo_qr": f"{codigo}-PB-H",
        "edificio": nombre,
        "planta": "Planta Baja",
        "genero": "Hombres",
        "estado_actual": "Fuera de Servicio" if codigo == "EDIF-H" else "Operativo",
        "posicion_x": x - 14,
        "posicion_y": y - 10,
    }
    _id += 1
    db_banos[_id] = {
        "id": _id,
        "codigo_qr": f"{codigo}-PB-M",
        "edificio": nombre,
        "planta": "Planta Baja",
        "genero": "Mujeres",
        "estado_actual": "Parcial" if codigo == "EDIF-C" else "Operativo",
        "posicion_x": x + 14,
        "posicion_y": y - 10,
    }
    _id += 1

db_reportes = []

# -------------------------------------------------------------------
# ALGORITMO DE NEGOCIO (SEMÁFORO)
# -------------------------------------------------------------------
def evaluar_algoritmo_semaforo(bano_id: int):
    ahora = datetime.now()
    hace_15_min = ahora - timedelta(minutes=15)
    
    reportes_recientes = [
        r for r in db_reportes 
        if r["bano_id"] == bano_id and r["fecha_hora"] >= hace_15_min and r["estado_reporte"] == "Pendiente"
    ]
    
    if not reportes_recientes:
        return
    
    fallas_criticas = sum(1 for r in reportes_recientes if r["tipo_incidencia"] in ["Sin agua en inodoros", "Fuga activa"])
    fallas_parciales = sum(1 for r in reportes_recientes if r["tipo_incidencia"] in ["Sin agua en lavamanos", "Baños Sucios"])
    reportes_positivos = sum(1 for r in reportes_recientes if r["tipo_incidencia"] == "Limpio y funcionando")
    
    bano = db_banos.get(bano_id)
    if not bano:
        return

    if reportes_positivos > 0 and fallas_criticas == 0 and fallas_parciales == 0:
        bano["estado_actual"] = "Operativo"
    elif fallas_criticas >= 1 or (fallas_parciales + fallas_criticas) >= 2:
        bano["estado_actual"] = "Fuera de Servicio"
    elif fallas_parciales == 1:
        bano["estado_actual"] = "Parcial"

# -------------------------------------------------------------------
# ENDPOINTS REST DE LA API
# -------------------------------------------------------------------

@app.get("/api/mapa/estatus", response_model=List[ModuloSanitarioDTO])
def obtener_estatus_global():
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
    for b in db_banos.values():
        if b["codigo_qr"] == codigo_qr:
            return b
    raise HTTPException(status_code=404, detail="Módulo sanitario no encontrado")

@app.post("/api/reportes", status_code=status.HTTP_201_CREATED)
def crear_reporte(datos: ReporteCrearDTO, request: Request):
    ip_cliente = request.client.host
    
    if not ValidadorSeguridad.validar_rate_limiting(ip_cliente, datos.bano_id):
        raise HTTPException(
            status_code=429, 
            detail="Ha enviado un reporte recientemente. Por favor espere 15 minutos."
        )
    
    comentario_seguro = ValidadorSeguridad.sanitizar_texto(datos.comentario or "")
    
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
    evaluar_algoritmo_semaforo(datos.bano_id)
    
    return {
        "mensaje": "Reporte registrado correctamente",
        "nuevo_estado": db_banos[datos.bano_id]["estado_actual"]
    }

# -------------------------------------------------------------------
# AUTENTICACIÓN Y PANEL ADMINISTRATIVO
# -------------------------------------------------------------------

@app.post("/api/admin/login")
def login_admin(datos: LoginAdminDTO):
    """CLASE 3 (UsuarioAdministrador): Inicio de sesión para personal de mantenimiento."""
    if datos.username == "admin" and datos.password == "mantenimiento123":
        token_sesion = f"token_admin_itl_session_{hash(datos.username)}"
        tokens_admin_activos.add(token_sesion)
        return {
            "token": token_sesion,
            "nombre": "Personal Mantenimiento ITL",
            "mensaje": "Inicio de sesión exitoso"
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Credenciales de administración incorrectas"
    )

def verificar_autenticacion_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials not in tokens_admin_activos:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Acceso denegado: Requiere inicio de sesión de mantenimiento"
        )
    return credentials.credentials

@app.put("/api/admin/incidencias/{bano_id}/resolver")
def resolver_incidencia_admin(
    bano_id: int, 
    token: str = Depends(verificar_autenticacion_admin)
):
    """Acción protegida: Restablece el sanitario a estado Operativo 🟢."""
    if bano_id not in db_banos:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    
    db_banos[bano_id]["estado_actual"] = "Operativo"
    for r in db_reportes:
        if r["bano_id"] == bano_id:
            r["estado_reporte"] = "Resuelto"
            
    return {"mensaje": f"Módulo {bano_id} restablecido a Verde (Operativo)"}