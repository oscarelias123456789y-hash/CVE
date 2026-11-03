#!/usr/bin/env python3
"""Consulta y exportación de vulnerabilidades CVE desde varias fuentes.

Fuentes: NVD (NIST) y CISA KEV.
Salida: Excel (.xlsx) con datos y gráficas nativas, y CSV para Power BI.

Uso interactivo:  python cve_tool.py
Uso por CLI:      python cve_tool.py --desde 2025-01-01 --hasta 2025-03-31 --fuentes nvd kev
"""
import argparse
import os
import sys
import time
from datetime import date, datetime, timedelta

import pandas as pd
import requests
from openpyxl.chart import BarChart, PieChart, Reference
from openpyxl.chart.label import DataLabelList

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
COLUMNAS = ["fuente", "cve_id", "fecha_publicacion", "descripcion", "severidad",
            "cvss", "vector", "cwe", "vendor", "producto", "url"]
ORDEN_SEVERIDAD = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SIN CALIFICAR"]
MAX_ANIOS = 5


# ---------- Fechas ----------
def parse_fecha(texto: str) -> date:
    return datetime.strptime(texto.strip(), "%Y-%m-%d").date()


def validar_rango(desde: date, hasta: date) -> None:
    limite = date.today() - timedelta(days=365 * MAX_ANIOS)
    if desde > hasta:
        raise ValueError("La fecha inicial no puede ser mayor que la final.")
    if desde < limite:
        raise ValueError(f"El rango debe estar dentro de los últimos {MAX_ANIOS} años (desde {limite}).")
    if hasta > date.today():
        raise ValueError("La fecha final no puede ser futura.")


# ---------- Fuente: NVD ----------
def consultar_nvd(desde: date, hasta: date) -> pd.DataFrame:
    """NVD limita cada consulta a 120 días, así que se divide el rango en bloques."""
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    pausa = 1 if api_key else 6  # límite: 5 peticiones/30s sin clave
    filas = []
    inicio = desde
    while inicio <= hasta:
        fin = min(inicio + timedelta(days=119), hasta)
        idx = 0
        while True:
            params = {
                "pubStartDate": f"{inicio}T00:00:00.000",
                "pubEndDate": f"{fin}T23:59:59.999",
                "resultsPerPage": 2000,
                "startIndex": idx,
            }
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
            r.raise_for_status()
            data = r.json()
            for item in data.get("vulnerabilities", []):
                filas.append(_fila_nvd(item["cve"]))
            idx += data.get("resultsPerPage", 0)
            print(f"  NVD {inicio} → {fin}: {idx}/{data.get('totalResults', 0)}")
            if idx >= data.get("totalResults", 0):
                break
            time.sleep(pausa)
        inicio = fin + timedelta(days=1)
        time.sleep(pausa)
    return pd.DataFrame(filas, columns=COLUMNAS)


def _fila_nvd(cve: dict) -> dict:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    cvss = {}
    for clave in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        if cve.get("metrics", {}).get(clave):
            cvss = cve["metrics"][clave][0]["cvssData"]
            break
    cwes = [d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])]
    return {
        "fuente": "NVD",
        "cve_id": cve["id"],
        "fecha_publicacion": cve.get("published", "")[:10],
        "descripcion": desc,
        "severidad": cvss.get("baseSeverity", ""),
        "cvss": cvss.get("baseScore", ""),
        "vector": cvss.get("vectorString", ""),
        "cwe": ", ".join(sorted(set(cwes))),
        "vendor": "",
        "producto": "",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
    }


# ---------- Fuente: CISA KEV ----------
def consultar_kev(desde: date, hasta: date) -> pd.DataFrame:
    r = requests.get(KEV_URL, timeout=60)
    r.raise_for_status()
    filas = []
    for v in r.json().get("vulnerabilities", []):
        f = parse_fecha(v["dateAdded"])
        if desde <= f <= hasta:
            filas.append({
                "fuente": "CISA KEV",
                "cve_id": v["cveID"],
                "fecha_publicacion": v["dateAdded"],
                "descripcion": v.get("shortDescription", ""),
                "severidad": "",
                "cvss": "",
                "vector": "",
                "cwe": ", ".join(v.get("cwes", [])) if isinstance(v.get("cwes"), list) else "",
                "vendor": v.get("vendorProject", ""),
                "producto": v.get("product", ""),
                "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            })
    print(f"  CISA KEV: {len(filas)} registros")
    return pd.DataFrame(filas, columns=COLUMNAS)


FUENTES = {"nvd": consultar_nvd, "kev": consultar_kev}


# ---------- Exportación ----------
def _tablas_resumen(df: pd.DataFrame):
    """Tablas que alimentan las gráficas: CVE por mes y CVE por severidad."""
    por_mes = (df.assign(mes=df["fecha_publicacion"].str[:7])
                 .groupby("mes").size().reset_index(name="total")
                 .sort_values("mes"))
    sev = df["severidad"].replace("", "SIN CALIFICAR").fillna("SIN CALIFICAR")
    por_sev = sev.value_counts().reset_index()
    por_sev.columns = ["severidad", "total"]
    por_sev["orden"] = por_sev["severidad"].map(
        {s: i for i, s in enumerate(ORDEN_SEVERIDAD)}).fillna(len(ORDEN_SEVERIDAD))
    por_sev = por_sev.sort_values("orden").drop(columns="orden")
    return por_mes, por_sev


def _agregar_graficas(ws, n_mes: int, n_sev: int) -> None:
    # Gráfica 1: barras, CVE por mes (tabla en columnas A:B)
    barras = BarChart()
    barras.type = "col"
    barras.title = "CVE por mes de publicación"
    barras.y_axis.title = "Cantidad de CVE"
    barras.x_axis.title = "Mes"
    barras.add_data(Reference(ws, min_col=2, min_row=1, max_row=n_mes + 1), titles_from_data=True)
    barras.set_categories(Reference(ws, min_col=1, min_row=2, max_row=n_mes + 1))
    barras.legend = None
    barras.x_axis.delete = False
    barras.y_axis.delete = False
    barras.dataLabels = DataLabelList()
    barras.dataLabels.showVal = True
    barras.width, barras.height = 22, 10
    ws.add_chart(barras, "G2")

    # Gráfica 2: circular, CVE por severidad (tabla en columnas D:E)
    pastel = PieChart()
    pastel.title = "CVE por severidad"
    pastel.add_data(Reference(ws, min_col=5, min_row=1, max_row=n_sev + 1), titles_from_data=True)
    pastel.set_categories(Reference(ws, min_col=4, min_row=2, max_row=n_sev + 1))
    pastel.dataLabels = DataLabelList()
    pastel.dataLabels.showPercent = True
    pastel.width, pastel.height = 14, 10
    ws.add_chart(pastel, "G23")


def exportar(df: pd.DataFrame, base: str) -> None:
    df = df.sort_values("fecha_publicacion", ascending=False)
    df.to_csv(f"{base}.csv", index=False, encoding="utf-8-sig")
    por_mes, por_sev = _tablas_resumen(df)

    with pd.ExcelWriter(f"{base}.xlsx", engine="openpyxl") as w:
        df.to_excel(w, sheet_name="CVE", index=False)
        ws = w.sheets["CVE"]
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        for col, ancho in zip("ABCDEFGHIJK", [10, 18, 16, 80, 12, 8, 45, 20, 18, 18, 45]):
            ws.column_dimensions[col].width = ancho

        por_mes.to_excel(w, sheet_name="Graficas", index=False, startrow=0, startcol=0)
        por_sev.to_excel(w, sheet_name="Graficas", index=False, startrow=0, startcol=3)
        wg = w.sheets["Graficas"]
        for col, ancho in zip("ABDE", [12, 10, 16, 10]):
            wg.column_dimensions[col].width = ancho
        _agregar_graficas(wg, len(por_mes), len(por_sev))
    print(f"Exportado: {base}.xlsx (con gráficas) y {base}.csv ({len(df)} filas)")


# ---------- Interfaz ----------
def modo_interactivo():
    hoy = date.today()
    print(f"Rango permitido: últimos {MAX_ANIOS} años (formato AAAA-MM-DD)")
    desde = parse_fecha(input("Fecha inicial: "))
    hasta = parse_fecha(input(f"Fecha final [{hoy}]: ") or str(hoy))
    print("Fuentes disponibles: 1) NVD  2) CISA KEV")
    sel = input("Elige (ej. 1,2): ")
    fuentes = [{"1": "nvd", "2": "kev"}[s.strip()] for s in sel.split(",") if s.strip() in ("1", "2")]
    return desde, hasta, fuentes


def main():
    p = argparse.ArgumentParser(description="Consulta de CVE por rango de fechas y fuente")
    p.add_argument("--desde", help="AAAA-MM-DD")
    p.add_argument("--hasta", help="AAAA-MM-DD")
    p.add_argument("--fuentes", nargs="+", choices=FUENTES.keys())
    p.add_argument("--salida", default="cve_resultado", help="nombre base de los archivos")
    a = p.parse_args()

    if a.desde and a.fuentes:
        desde, hasta, fuentes = parse_fecha(a.desde), parse_fecha(a.hasta or str(date.today())), a.fuentes
    else:
        desde, hasta, fuentes = modo_interactivo()

    try:
        validar_rango(desde, hasta)
    except ValueError as e:
        sys.exit(f"Error: {e}")
    if not fuentes:
        sys.exit("Error: selecciona al menos una fuente.")

    frames = []
    for f in fuentes:
        print(f"Consultando {f.upper()}...")
        try:
            frames.append(FUENTES[f](desde, hasta))
        except requests.RequestException as e:
            print(f"  Fallo en {f}: {e}")
    if not frames:
        sys.exit("No se obtuvieron datos.")
    df = pd.concat(frames, ignore_index=True)
    if df.empty:
        sys.exit("No hay CVE en ese rango de fechas.")
    exportar(df, a.salida)


if __name__ == "__main__":
    main()
