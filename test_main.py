import pytest
from fastapi.testclient import TestClient
from main import app, ValidadorSeguridad

client = TestClient(app)

# -------------------------------------------------------------------
# 1. PRUEBAS DE CONSULTA PÚBLICA (MAPA Y QR)
# -------------------------------------------------------------------
def test_obtener_estatus_mapa():
    response = client.get("/api/mapa/estatus")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "codigo_qr" in data[0]
    assert "estado_semaforo" in data[0]

def test_consultar_bano_por_qr_exitoso():
    response = client.get("/api/modulos/EDIF-D-PB-H")
    assert response.status_code == 200
    data = response.json()
    assert data["codigo_qr"] == "EDIF-D-PB-H"
    assert data["edificio"] == "Edificio D - Sistemas"

def test_consultar_bano_por_qr_inexistente():
    response = client.get("/api/modulos/QR-INEXISTENTE-999")
    assert response.status_code == 404
    assert response.json()["detail"] == "Módulo sanitario no encontrado"

# -------------------------------------------------------------------
# 2. PRUEBAS DE SEGURIDAD (ANTI-SPAM Y XSS)
# -------------------------------------------------------------------
def test_validador_sanitizacion_xss():
    entrada_riesgosa = "<script>alert('hack')</script> Baño sucio"
    texto_seguro = ValidadorSeguridad.sanitizar_texto(entrada_riesgosa)
    assert "<script>" not in texto_seguro
    assert "&lt;script&gt;" in texto_seguro

def test_rate_limiting_anti_spam():
    ip = "192.168.1.50"
    bano_id = 1
    assert ValidadorSeguridad.validar_rate_limiting(ip, bano_id) == True
    assert ValidadorSeguridad.validar_rate_limiting(ip, bano_id) == False

# -------------------------------------------------------------------
# 3. PRUEBA DEL ALGORITMO DE SEMÁFORO AUTOMÁTICO
# -------------------------------------------------------------------
def test_algoritmo_semaforo_cambio_a_rojo():
    ValidadorSeguridad.registro_envios.clear()
    
    res = client.post("/api/reportes", json={
        "bano_id": 2,
        "tipo_incidencia": "Sin agua en inodoros",
        "comentario": "No sale agua de los inodoros"
    })
    assert res.status_code == 201

    response = client.get("/api/modulos/EDIF-D-PB-M")
    assert response.status_code == 200
    assert response.json()["estado_actual"] == "Fuera de Servicio"

# -------------------------------------------------------------------
# 4. PRUEBAS DE AUTENTICACIÓN Y RESOLUCIÓN ADMIN
# -------------------------------------------------------------------
def test_login_admin_exitoso():
    response = client.post("/api/admin/login", json={
        "username": "admin",
        "password": "mantenimiento123"
    })
    assert response.status_code == 200
    assert "token" in response.json()

def test_login_admin_incorrecto():
    response = client.post("/api/admin/login", json={
        "username": "admin",
        "password": "password_incorrecta"
    })
    assert response.status_code == 401

def test_resolver_incidencia_sin_auth():
    response = client.put("/api/admin/incidencias/2/resolver")
    assert response.status_code in [401, 403]

def test_resolver_incidencia_admin_autenticado():
    res_login = client.post("/api/admin/login", json={
        "username": "admin",
        "password": "mantenimiento123"
    })
    token = res_login.json()["token"]
    
    response = client.put(
        "/api/admin/incidencias/2/resolver",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    
    response_bano = client.get("/api/modulos/EDIF-D-PB-M")
    assert response_bano.json()["estado_actual"] == "Operativo"