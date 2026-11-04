# Consulta y visualización de vulnerabilidades CVE

Programa en Python que consulta vulnerabilidades CVE en varias fuentes, filtra por rango de fechas (máximo últimos 5 años) y exporta los datos a Excel (con gráficas) y CSV para visualizarlos en Excel o Power BI.

## Fuentes
- **NVD** (NIST): API 2.0, con CVSS, severidad y CWE.
- **CISA KEV**: catálogo de vulnerabilidades explotadas activamente.

## Instalación
```bash
pip install -r requirements.txt
```

## Uso
Interactivo:
```bash
python cve_tool.py
```
Por línea de comandos:
```bash
python cve_tool.py --desde 2025-01-01 --hasta 2025-03-31 --fuentes nvd kev --salida resultado
```
Opcional: define `NVD_API_KEY` para consultas más rápidas en NVD.

## Salida
- `*.xlsx`
  - Hoja `CVE`: todos los datos, con filtros y encabezado fijo.
  - Hoja `Graficas`: tablas resumen y dos gráficas nativas de Excel:
    - Barras: CVE por mes de publicación.
    - Circular: CVE por severidad.
- `*.csv`: para importar en Power BI (Obtener datos → Texto/CSV).

## Power BI
Importa el CSV y crea: gráfico de barras por `severidad`, línea por mes de `fecha_publicacion`, y tabla con `cve_id`, `cvss` y `descripcion`.
