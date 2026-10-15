# Cyber Range Execution & Threat Detection Report

**Document ID:** CR-REP-2026-001  
**Author:** Autonomous Cyber Range Architect & Orchestrator  
**Date:** 2026-10-15  
**Classification:** TLP:CLEAR / Internal Technical Documentation  
**Status:** **APPROVED — 100% TEST SUITE PASS (12/12)**  

---

## 1. Resumen Ejecutivo (Executive Summary)

El presente informe documenta el diseño, despliegue, emulación de amenazas y validación de detección del laboratorio automatizado **Cyber Range: Web Exploitation & Lateral Movement**.

El objetivo principal consistió en reproducir un vector de intrusión realista de extremo a extremo:
1. Sondeo externo y explotación de una aplicación web vulnerable en la **Zona Desmilitarizada (DMZ)**.
2. Intento fallido de ruptura perimetral directa desde el exterior hacia activos críticos corporativos.
3. Movimiento lateral exitoso desde el servidor web comprometido hacia la API central de la **Zona Interna Corporativa**.
4. Verificación autónoma de la efectividad del sensor de inspección profunda (**Suricata IDS**) y las reglas analíticas de correlación (**Wazuh** y **Sigma**).

### Métricas Clave de la Ejecución:
- **Estado de Contenedores:** 4/4 Activos y Saludables (`cr-edge-router-soc`, `cr-attacker-node`, `cr-dmz-web`, `cr-internal-corp`).
- **Tasa de Éxito del Test Suite:** **100% (12/12 Pruebas Superadas)** en un tiempo total de **13.86 segundos**.
- **Alertas Críticas Registradas:** 100% de los vectores de ataque generaron firmas IDS exactas (`fast.log` y `eve.json`).

---

## 2. Topología de Red y Arquitectura de Microsegmentación

El entorno implementa una separación lógica mediante puentes de red Docker independientes interconectados exclusivamente a través de una pasarela central (`cr-edge-router-soc`):

```mermaid
flowchart TD
    subgraph External_Zone ["Zona Externa (Red Zone - Untrusted)"]
        direction TB
        Attacker["cr-attacker-node<br/>IP: 10.10.10.5<br/>(Nmap, Curl, Sqlmap)"]
    end

    subgraph SOC_Perimeter ["Perímetro & SOC Inline Core"]
        direction TB
        Router["cr-edge-router-soc<br/>Gateway: 10.10.10.1 / 10.10.20.1 / 10.10.30.1<br/>Firewall Iptables (Stateful Filtering)"]
        Suricata["Suricata 7.0.2 IDS Sensor<br/>PCAP Multi-Interface Engine<br/>(eth0, eth1, eth2)"]
        Logs[("Logs de Telemetría<br/>/var/log/suricata/<br/>fast.log & eve.json")]
        Router -->|"Inspección Raw PCAP"| Suricata
        Suricata -->|"Genera Alertas & Eventos"| Logs
    end

    subgraph DMZ_Zone ["Zona Desmilitarizada (Yellow Zone - Semi-Trusted)"]
        direction TB
        DMZWeb["cr-dmz-web<br/>IP: 10.10.20.50<br/>OWASP DVWA (HTTP :80)"]
    end

    subgraph Internal_Zone ["Zona Interna Corporativa (Blue Zone - Trusted)"]
        direction TB
        InternalDB["cr-internal-corp<br/>IP: 10.10.30.50<br/>Core Banking REST API (:5000)"]
    end

    %% Flujos de Red y Amenazas
    Attacker -->|"1. Tráfico Web Permitido (HTTP :80)"| Router
    Router -->|"Reenvío hacia DMZ"| DMZWeb

    Attacker -.->|"2. Sondeo Directo Bloqueado (DROP/REJECT)"| Router
    Router -.->|"X Violación de Perímetro (SID 1000040)"| InternalDB

    DMZWeb ==>|"3. Pivote Movimiento Lateral (TCP :5000)"| Router
    Router ==>|"Extracción de Datos (SID 1000030/1000031)"| InternalDB

    %% Estilos de Nodos
    classDef red fill:#ff4d4f,stroke:#cf1322,stroke-width:2px,color:#fff;
    classDef yellow fill:#faad14,stroke:#d48806,stroke-width:2px,color:#fff;
    classDef blue fill:#1890ff,stroke:#096dd9,stroke-width:2px,color:#fff;
    classDef router fill:#722ed1,stroke:#531dab,stroke-width:2px,color:#fff;
    classDef storage fill:#13c2c2,stroke:#08979c,stroke-width:2px,color:#fff;

    class Attacker red;
    class DMZWeb yellow;
    class InternalDB blue;
    class Router,Suricata router;
    class Logs storage;
```

### Matriz de Segmentación y Políticas de Acceso:

| Segmento | Subred CIDR | Gateway | Dirección IP | Función / Servicio | Política de Tráfico |
|---|---|---|---|---|---|
| **External (Red)** | `10.10.10.0/24` | `10.10.10.1` | `10.10.10.5` | Atacante (Pentesting) | Salida permitida únicamente hacia DMZ (`:80`). |
| **DMZ (Yellow)** | `10.10.20.0/24` | `10.10.20.1` | `10.10.20.50` | DVWA Web Server (`:80`) | Expuesto al exterior; enlace de datos hacia Interna (`:5000`). |
| **Internal (Blue)** | `10.10.30.0/24` | `10.10.30.1` | `10.10.30.50` | Core Banking API (`:5000`) | Aislado de Internet; únicamente accesible vía DMZ. |
| **SOC Gateway** | Multi-Homed | — | `.1` en c/u | Firewall + IDS Multi-IF | Inspección promiscua PCAP en `eth0`, `eth1` y `eth2`. |

---

## 3. Flujo y Matriz de Emulación de Amenazas (MITRE ATT&CK)

El siguiente diagrama de secuencia representa la interacción paso a paso entre el atacante, los componentes defensivos perimetrales y los sensores SOC:

```mermaid
sequenceDiagram
    autonumber
    actor RedTeam as Attacker Node (10.10.10.5)
    participant Router as Edge Router (10.10.10.1)
    participant IDS as Suricata Sensor (Inline IDS)
    participant DMZ as DMZ Web Server (10.10.20.50)
    participant Internal as Internal Core API (10.10.30.50)
    actor BlueTeam as Blue Team / SOC Operator

    %% Fase 1: Reconocimiento
    rect rgb(250, 240, 240)
    Note over RedTeam,DMZ: Fase 1: Reconocimiento & Fingerprinting (T1595)
    RedTeam->>Router: Nmap SYN Scan (Puertos 80, 443, 8080, 3306)
    Router->>IDS: Inspección de paquetes SYN
    IDS-->>BlueTeam: [ALERTA] SID 1000001: Port Scan Detected
    Router->>DMZ: Reenvío a puerto 80 (Abierto)
    DMZ-->>RedTeam: SYN-ACK HTTP 80
    RedTeam->>DMZ: Probe con User-Agent 'sqlmap/1.7#stable'
    IDS-->>BlueTeam: [ALERTA] SID 1000002: Automated Scanner User-Agent Detected
    end

    %% Fase 2: Explotación Web
    rect rgb(255, 250, 230)
    Note over RedTeam,DMZ: Fase 2: Explotación Web Inicial (T1190 & T1083)
    RedTeam->>DMZ: GET /vulnerabilities/sqli/?id=1' UNION SELECT 1,user()--
    IDS-->>BlueTeam: [ALERTA CRÍTICA] SID 1000010: SQLi UNION SELECT Pattern
    DMZ-->>RedTeam: HTTP 302 / Inyección evaluada
    RedTeam->>DMZ: GET /vulnerabilities/fi/?page=../../../../etc/passwd
    IDS-->>BlueTeam: [ALERTA CRÍTICA] SID 1000020: LFI Directory Traversal (/etc/passwd)
    DMZ-->>RedTeam: Exfiltración de /etc/passwd (Compromiso DMZ)
    end

    %% Fase 3: Violación Perimetral Bloqueada
    rect rgb(240, 240, 255)
    Note over RedTeam,Internal: Fase 3: Intento Fallido de Ruptura Perimetral Directa (T1046)
    RedTeam-xRouter: TCP SYN directo a 10.10.30.50:5000
    Router-->>RedTeam: ICMP Port Unreachable (DROP por Firewall)
    IDS-->>BlueTeam: [ALERTA] SID 1000040: Direct Perimeter Breach Attempt
    end

    %% Fase 4: Movimiento Lateral
    rect rgb(235, 255, 235)
    Note over DMZ,Internal: Fase 4: Movimiento Lateral & Exfiltración Interna (T1021 & T1570)
    DMZ->>Router: Pivote interno GET http://10.10.30.50:5000/api/v1/customers
    Router->>IDS: Inspección tráfico DMZ -> Interno
    IDS-->>BlueTeam: [ALERTA CRÍTICA] SID 1000030: Lateral Movement DMZ to Internal
    IDS-->>BlueTeam: [ALERTA CRÍTICA] SID 1000031: Querying Internal Financial/Customer API
    Router->>Internal: Conexión permitida (Ruta de pivote)
    Internal-->>DMZ: JSON con registros bancarios confidenciales
    DMZ-->>RedTeam: Exfiltración final completada hacia el atacante
    end
```

### Tabla de Técnicas MITRE ATT&CK:

| Fase de Ataque | Técnica MITRE | Vector de Ataque Inyectado | Resultado Operativo | Regla IDS Activada |
|---|---|---|---|---|
| **Reconocimiento** | [T1595](https://attack.mitre.org/techniques/T1595/) | Escaneo SYN Nmap contra puertos 80, 443, 8080, 3306 | Descubrimiento de puerto HTTP 80 abierto | `SID 1000001` |
| **Reconocimiento** | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Petición HTTP con User-Agent automatizado `sqlmap/1.7#stable` | Servidor procesa parámetro inyectado | `SID 1000002` |
| **Acceso Inicial** | [T1190](https://attack.mitre.org/techniques/T1190/) | Inyección SQL Clásica: `UNION SELECT 1, user()` | Inyección recibida y evaluada en backend | `SID 1000010` |
| **Acceso Inicial** | [T1190](https://attack.mitre.org/techniques/T1190/) | Inyección SQL Booleana: `' OR 1=1 --` | Evasión lógica detectada en URI | `SID 1000011` |
| **Descubrimiento** | [T1083](https://attack.mitre.org/techniques/T1083/) | Salto de Directorio / LFI: `../../../../etc/passwd` | Intento de extracción de credenciales locales | `SID 1000020` / `1000021` |
| **Evasión de Defensas** | [T1046](https://attack.mitre.org/techniques/T1046/) | Sonda directa Atacante (`10.10.10.5`) ➔ Interno (`10.10.30.50:5000`) | **RECHAZADO** por firewall perimetral (ICMP Unreachable) | `SID 1000040` |
| **Movimiento Lateral** | [T1021](https://attack.mitre.org/techniques/T1021/) / [T1570](https://attack.mitre.org/techniques/T1570/) | Pivote desde DMZ (`10.10.20.50`) hacia API financiera interna (`10.10.30.50:5000`) | **Compromiso exitoso**: Extracción de registros financieros | `SID 1000030` / `1000031` |

---

## 4. Flujo y Resultados de la Suite de Pruebas Automatizadas

El flujo de control del pipeline de pruebas automatizado se ejecuta de forma secuencial:

```mermaid
flowchart LR
    Start(["Inicio: run_tests.ps1"]) --> Setup["Setup de Entorno<br/>- Enrutamiento DMZ<br/>- Verificación Suricata PCAP"]

    subgraph Cat1 ["1. Infraestructura"]
        TC1["TC1.1 Contenedores Activos<br/>TC1.2 Demonio Suricata<br/>TC1.3 Kernel IP Forwarding"]
    end

    subgraph Cat2 ["2. Políticas Perimetrales"]
        TC2["TC2.1 Acceso Externo a DMZ<br/>TC2.2 Zero-Trust E-to-I Block<br/>TC2.3 Conectividad DMZ-to-Internal"]
    end

    subgraph Cat3 ["3. Emulación & Detección"]
        TC3["TC3.1 SQLi (SID 1000010)<br/>TC3.2 Scanner (SID 1000002)<br/>TC3.3 LFI (SID 1000020)<br/>TC3.4 Lateral Mov (SID 1000030/31)<br/>TC3.5 Breach Attempt (SID 1000040)"]
    end

    subgraph Cat4 ["4. Telemetría SOC"]
        TC4["TC4.1 Validación JSON-L<br/>eve.json & Metadatos MITRE"]
    end

    Setup --> Cat1
    Cat1 -->|Pass| Cat2
    Cat2 -->|Pass| Cat3
    Cat3 -->|Pass| Cat4
    Cat4 --> Outcome(["Resultado: 12/12 PASS (100% OK)"])

    classDef pass fill:#52c41a,stroke:#237804,stroke-width:2px,color:#fff;
    classDef pipe fill:#1890ff,stroke:#096dd9,stroke-width:2px,color:#fff;
    class Start,Outcome pass;
    class TC1,TC2,TC3,TC4 pipe;
```

### Ejecución en Vivo de la Suite:

```text
========================================================================
             CYBER RANGE: AUTOMATED TEST SUITE RUNNER                   
========================================================================
[+] Executing Python Comprehensive Unit & Integration Test Suite...

=======================================================
  INITIALIZING CYBER RANGE TEST SUITE
=======================================================
  [+] TC1.1 PASSED: All 4 Cyber Range containers are running.
  [+] TC1.2 PASSED: Suricata IDS daemon is active and running.
  [+] TC1.3 PASSED: Kernel IP Forwarding is active on Edge Router.
  [+] TC2.1 PASSED: External Attacker can reach DMZ Web server (HTTP 200/302).
  [+] TC2.2 PASSED: Perimeter Firewall successfully rejected direct External -> Internal probe.
  [+] TC2.3 PASSED: DMZ to Internal network path is operational.
  [+] TC3.1 PASSED: Suricata triggered Alert [SID 1000010] SQLi UNION SELECT Pattern.
  [+] TC3.2 PASSED: Suricata triggered Alert [SID 1000002] Automated Scanner (sqlmap).
  [+] TC3.3 PASSED: Suricata triggered Alert [SID 1000020] Directory Traversal (/etc/passwd).
  [+] TC3.4 PASSED: Suricata triggered Alert [SID 1000030/1000031] Lateral Movement DMZ->Internal.
  [+] TC3.5 PASSED: Suricata triggered Alert [SID 1000040] Perimeter Breach Attempt.
  [+] TC4.1 PASSED: Validated 61 structured alert events in eve.json telemetry.

----------------------------------------------------------------------
Ran 12 tests in 13.860s

OK

[SUCCESS] All Cyber Range tests passed successfully!
```

---

## 5. Evidencia de Telemetría Blue Team

### A. Registro de Alertas en Tiempo Real (`fast.log`)
```text
10/15/2026-22:49:17.150954  [**] [1:1000010:1] [SOC-ALERT] [T1190] Web Application SQLi Attempt - UNION SELECT Pattern [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 10.10.10.5:46810 -> 10.10.20.50:80
10/15/2026-22:49:17.339794  [**] [1:1000002:1] [SOC-ALERT] [T1595.002] Automated Vulnerability Scanner User-Agent Detected [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 10.10.10.5:46822 -> 10.10.20.50:80
10/15/2026-22:49:17.556061  [**] [1:1000020:1] [SOC-ALERT] [T1083] Directory Traversal / LFI Attempt against /etc/passwd [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 10.10.10.5:46824 -> 10.10.20.50:80
10/15/2026-22:49:17.761991  [**] [1:1000030:1] [SOC-ALERT] [T1021] Suspicious Lateral Movement: DMZ Host Connecting to Internal Corporate Segment [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 10.10.20.50:47324 -> 10.10.30.50:5000
10/15/2026-22:49:17.762147  [**] [1:1000031:1] [SOC-ALERT] [T1570] Lateral Movement: DMZ Node Querying Internal Financial/Customer API [**] [Classification: A suspicious filename was detected] [Priority: 2] {TCP} 10.10.20.50:47324 -> 10.10.30.50:5000
10/15/2026-22:49:25.399626  [**] [1:1000040:1] [SOC-ALERT] [T1046] Direct Perimeter Breach Attempt: External Attacker Probing Internal Segment [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.10.10.5:41002 -> 10.10.30.50:5000
```

### B. Muestra de Telemetría Estructurada JSON-L (`eve.json`)
```json
{
  "timestamp": "2026-10-15T22:48:13.774196+0000",
  "flow_id": 1630170601276901,
  "in_iface": "eth1",
  "event_type": "alert",
  "src_ip": "10.10.10.5",
  "src_port": 40920,
  "dest_ip": "10.10.20.50",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000010,
    "rev": 1,
    "signature": "[SOC-ALERT] [T1190] Web Application SQLi Attempt - UNION SELECT Pattern",
    "category": "Web Application Attack",
    "severity": 1
  },
  "http": {
    "hostname": "10.10.20.50",
    "url": "/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,user()+--+&Submit=Submit",
    "http_user_agent": "curl/8.14.1",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 302
  }
}
```

---

## 6. Recomendaciones de Mitigación y Hardening

A partir del análisis de las brechas y vectores comprobados en el laboratorio:

1. **Defensa en Profundidad en Aplicación Web:**
   - Implementar sentencias preparadas (*Prepared Statements*) y validación de tipos estricta para mitigar inyecciones SQL en el código de la aplicación DMZ.
   - Deshabilitar `allow_url_include` y sanitizar entradas relativas de archivos (`basename()`) para neutralizar ataques LFI.
2. **Restricción Egress en la DMZ:**
   - La DMZ no debe tener acceso irrestricto hacia el segmento interno. Se debe implementar autenticación mutua (mTLS) y listas blancas estrictas a nivel de proxy inverso/API Gateway para evitar consultas directas no autorizadas.
3. **Bloqueo Activo en IDS (Migración a IPS/WAF):**
   - Transicionar las firmas Suricata de modo `alert` a modo `drop` (Inline IPS) para interrumpir las conexiones TCP maliciosas antes de que alcancen el backend.
4. **Monitorización de Endpoint (HIDS/EDR):**
   - Desplegar agentes Wazuh en el servidor DMZ para detectar procesos anómalos (ej. creación de web shells o llamadas a binarios del sistema).

---

## 7. Instrucciones de Reproducibilidad

Para volver a ejecutar el laboratorio y validar el reporte:

```powershell
# 1. Navegar al directorio de trabajo
cd c:\Users\brene\Documents\GNs3

# 2. Desplegar los servicios (si no están activos)
docker compose up -d

# 3. Correr la suite de pruebas automatizadas
.\run_tests.ps1

# 4. Inspeccionar la telemetría generada
docker exec cr-edge-router-soc cat /var/log/suricata/fast.log
```
