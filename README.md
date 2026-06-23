# DAST-Сканер уязвимостей 

## 🛠 Установка и настройка

1. **Системные требования:** 
   - Python 3.9+
   - Установленные браузерные зависимости для Playwright.

2. **Установка зависимостей:**
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```

---

##  Режимы работы и запуск сканера

Основной исполняемый модуль — `my_scan.scanner`.

### Базовый запуск (Анонимное сканирование)
```bash
python3 -m my_scan.scanner http://target-app.local ./output_results
```
- `http://target-app.local` — целевой URL.
- `./output_results` — директория, куда будут сохранены отчеты (`app_map.json`, HTML-дашборд и др.).

### Сканирование с аутентификацией (через учетные данные)
Если приложение содержит форму авторизации:
```bash
python3 -m my_scan.scanner http://target-app.local ./output_results \
    --username admin \
    --password P@ssw0rd123!
```

### Сканирование с аутентификацией (через сессионные Cookie)
Если авторизация сложная (например, OAuth, MFA), можно авторизоваться вручную в браузере, собрать JSON-куки и передать их сканеру:
```bash
python3 -m my_scan.scanner http://target-app.local ./output_results \
    --cookies '[{"name": "session_id", "value": "xyz123", "domain": "target-app.local", "path": "/"}]'
```

### Настройка глубины и лимитов
Для предотвращения бесконечного обхода:
```bash
python3 -m my_scan.scanner http://target-app.local ./output_results \
    --max-depth 3 \
    --max-urls 200
```
- `--max-depth` — максимальная глубина перехода по ссылкам от стартовой страницы.
- `--max-urls` — лимит уникальных эндпоинтов для парсинга.

### Использование прокси (для отладки через Burp Suite / Mitmproxy)
```bash
python3 -m my_scan.scanner http://target-app.local ./output_results \
    --proxy http://127.0.0.1:8080
```

---

## Тестовый стенд и бенчмаркинг

В папке `stand` находится конфигурация для автоматизированного развертывания уязвимых приложений-мишеней (Online Boutique и Unguard) и их сканирования в Docker-окружении.

**Запуск полного цикла тестирования (развертывание + сканирование + расчет метрик):**
```bash
./run_tests.sh
```

**Что делает скрипт `run_tests.sh`:**
1. Разворачивает приложение **Online Boutique** в Kubernetes / Docker.
2. Запускает DAST-сканер на N итераций для сбора метрик.
3. Рассчитывает Precision/Recall метрики сканера, сравнивая найденные уязвимости с эталонным файлом (`ground_truth_goo.json`).
4. Повторяет тот же процесс для микросервисного приложения **Unguard** (с эталоном `ground_truth_un.json`).
5. Сохраняет сводку по метрикам в `metrics_summary.txt`.

---
## Структура проекта

- `my_scan/crawler.py` — модуль обхода SPA с использованием Playwright (перехват XHR, клики, сбор форм).
- `my_scan/analyzer.py` — эвристический анализатор (поиск потенциальных инъекций и аномалий).
- `my_scan/attack.py` — боевой модуль (отправка пейлоадов и верификация уязвимостей).
- `my_scan/report_generator.py` — генерация графических HTML и JSON отчетов.
- `stand/` — Docker Compose файлы и скрипты (оркестраторы) для развертывания уязвимых стендов.
- `scratch/analyze_results.py` — утилита для автоматического расчета метрик эффективности (F1-score, Precision, Recall).
