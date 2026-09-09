#!/bin/bash

echo "============================================================"
echo "PROJECT 2: WINDOWS DETECTION PLATFORM"
echo "FULL PIPELINE"
echo "============================================================"

echo ""
echo "[1/8] Parsing Sysmon Events..."
python event_parser.py

echo ""
echo "[2/8] Building Baselines..."
python baseline_engine.py

echo ""
echo "[3/8] Running Sigma Engine..."
python sigma_engine.py

echo ""
echo "[4/8] Running Detection Engine..."
python detection_engine.py

echo ""
echo "[5/8] Running Threat Intelligence..."
python threat_intel_engine.py

echo ""
echo "[6/8] Running MITRE ATT&CK Mapping..."
python mitre_mapper.py

echo ""
echo "[7/8] Exporting SIEM Reports..."
python siem_exporter.py

echo ""
echo "[8/8] Starting Dashboard..."
echo ""
echo "Dashboard URL:"
echo "http://127.0.0.1:5000"
echo ""

python dashboard.py
