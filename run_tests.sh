#!/usr/bin/env bash

# Остановка скрипта при ошибке
set -e

echo "============================================="
echo "   1. RUNNING TESTING FOR ONLINE BOUTIQUE"
echo "============================================="
cd /Users/mac/Desktop/sacner/scaner_1/stand
# Флаг --build гарантирует, что мы подтягиваем последние изменения сканера/оркестратора
docker compose up orchestrator-goo

echo "============================================="
echo "   2. CALCULATING METRICS FOR ONLINE BOUTIQUE"
echo "============================================="
cd /Users/mac/Desktop/sacner/scaner_1
python3 scratch/analyze_results.py results_goo ground_truth_goo.json
echo ""

echo "============================================="
echo "   3. RUNNING TESTING FOR UNGUARD"
echo "============================================="
cd /Users/mac/Desktop/sacner/scaner_1/stand
# Используем обычный оркестратор для старого приложения (Unguard)
docker compose up orchestrator

echo "============================================="
echo "   4. CALCULATING METRICS FOR UNGUARD"
echo "============================================="
cd /Users/mac/Desktop/sacner/scaner_1
# В качестве эталона используется ground_truth_un.json
python3 scratch/analyze_results.py my_scan/results_un ground_truth_un.json
echo ""

echo "============================================="
echo "   ALL DONE!"
echo "   Results saved to: "
echo "   - results_goo/metrics_summary.txt"
echo "   - my_scan/results_un/metrics_summary.txt"
echo "============================================="
