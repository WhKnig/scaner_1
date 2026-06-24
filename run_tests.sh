#!/usr/bin/env bash

# Остановка скрипта при ошибке
set -e

echo "============================================="
echo "   1. RUNNING TESTING FOR ONLINE BOUTIQUE"
echo "============================================="
cd /Users/mac/Desktop/sacner/scaner_1/stand
# Флаг --build гарантирует, что мы подтягиваем последние изменения сканера/оркестратора
docker compose up orchestrator-goo --build

echo "============================================="
echo "   2. CALCULATING METRICS FOR ONLINE BOUTIQUE"
echo "============================================="
cd /Users/mac/Desktop/sacner/scaner_1
python3 my_scan/scratch/analyze_results.py results_goo test_data/ground_truth_goo.json test_data/secure_endpoints_goo.json
echo ""

echo "============================================="
echo "   3. RUNNING TESTING FOR UNGUARD"
echo "============================================="
cd /Users/mac/Desktop/sacner/scaner_1/stand
# Используем обычный оркестратор для старого приложения (Unguard)
docker compose up orchestrator --build

echo "============================================="
echo "   4. CALCULATING METRICS FOR UNGUARD"
echo "============================================="
cd /Users/mac/Desktop/sacner/scaner_1
# В качестве эталона используется ground_truth_un.json
python3 my_scan/scratch/analyze_results.py my_scan/results_un test_data/ground_truth_un.json test_data/secure_endpoints_un.json
echo ""

echo "============================================="
echo "   ALL DONE!"
echo "   Results saved to: "
echo "   - results_goo/metrics_summary.txt"
echo "   - my_scan/results_un/metrics_summary.txt"
echo "============================================="
