# Cyber Range: Web Attack & Lateral Movement Detection Lab

Laboratorio automatizado multi-segmento diseñado para entrenamiento y pruebas de **Red Team**, **Blue Team** y **Purple Team**.

> [!TIP]
> 📚 **Material Pedagógico:** Consulta la [Guía Práctica para Estudiantes (GUIA_ESTUDIANTE.md)](GUIA_ESTUDIANTE.md) para realizar paso a paso los ejercicios del laboratorio, y el [Informe Técnico (report.md)](report.md) para el análisis forense de telemetría y hardening.

---

## 1. Arquitectura de Red y Topología

El entorno implementa una segmentación estricta de 3 zonas controlada por un Router/Firewall perimetral con sensor IDS Suricata en línea:

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

    %% Flujos de Tráfico y Ataque
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

### Tabla de Direccionamiento IP y Políticas:

| Segmento / Zona | CIDR / Subred | Gateway | IP Asignada | Rol / Función | Tecnologías |
|---|---|---|---|---|---|
| **External (Red Zone)** | `10.10.10.0/24` | `10.10.10.1` | `10.10.10.5` | Nodo Atacante (Pentest Tools) | Alpine Security, Nmap, Curl, Sqlmap |
| **DMZ (Yellow Zone)** | `10.10.20.0/24` | `10.10.20.1` | `10.10.20.50` | Aplicación Web Vulnerable | OWASP DVWA (HTTP :80) |
| **Internal (Blue Zone)** | `10.10.30.0/24` | `10.10.30.1` | `10.10.30.50` | Base de Datos / API Corporativa | Python REST Core API (:5000) |
| **SOC / Core Router** | Multi-homed | — | `.1` en c/u | Firewall perimetral + Sensor IDS | Iptables + Suricata IDS Inline |

### Políticas de Tráfico Perimetral
- **Attacker (10.10.10.0/24) ➔ DMZ (10.10.20.50:80):** PERMITIDO (Simula servicio web expuesto a Internet).
- **Attacker (10.10.10.0/24) ➔ Internal (10.10.30.0/24):** DENEGADO / RECHAZADO (Defensa perimetral estricta).
- **DMZ (10.10.20.0/24) ➔ Internal (10.10.30.50:5000):** PERMITIDO (Ruta crítica aprovechada para Movimiento Lateral).

---

## 2. Métodos de Despliegue

### Opción A: Despliegue Inmediato con Docker Compose (Micro-Lab)
Requisitos: Docker & Docker Compose.

```bash
# Iniciar todos los contenedores y el sensor Suricata
docker compose up -d --build

# Verificar estado de los contenedores
docker compose ps
```

### Opción B: Despliegue en GNS3 (Topología de Red Virtual)
Requisitos: GNS3 Server corriendo en `http://localhost:3080` con API REST habilitada.

```bash
# Instalar dependencias opcionales
pip install gns3fy requests

# Desplegar topología automáticamente en GNS3
python gns3_topology_deploy.py --host http://localhost:3080 --project CyberRange_Web_LateralMovement
```

---

## 3. Flujo de Emulación de Amenazas (Attack Lifecycle)

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

### Plan de Ejecución Autónomo:
```bash
# Ejecución en Linux / macOS / WSL:
chmod +x emulation_attack_and_detect.sh
./emulation_attack_and_detect.sh

# Ejecución en Windows (PowerShell):
.\emulation_attack_and_detect.ps1
```

---

## 4. Mapeo MITRE ATT&CK y Reglas de Detección

| Fase | Técnica MITRE | Vector de Ataque | Regla Suricata (SID) | Regla Wazuh |
|---|---|---|---|---|
| **Reconnaissance** | [T1595](https://attack.mitre.org/techniques/T1595/) | Nmap Port Scan & Sqlmap User-Agent | `1000001`, `1000002` | `100100` |
| **Initial Access** | [T1190](https://attack.mitre.org/techniques/T1190/) | SQL Injection (`UNION SELECT`, `OR 1=1`) | `1000010`, `1000011` | `100100` |
| **Discovery** | [T1083](https://attack.mitre.org/techniques/T1083/) | Path Traversal / LFI (`/etc/passwd`) | `1000020`, `1000021` | `100101` |
| **Lateral Movement** | [T1021](https://attack.mitre.org/techniques/T1021/) | DMZ Web Server Pivot a Internal API | `1000030`, `1000031` | `100102` |
| **Defense Evasion** | [T1046](https://attack.mitre.org/techniques/T1046/) | Sonda directa Atacante a Red Interna | `1000040` | `100103` |

---

## 5. Pipeline de Pruebas Automatizadas (Test Suite)

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

```powershell
# Ejecución en Windows PowerShell
.\run_tests.ps1

# O directamente con Python
python tests\test_cyber_range.py
```
