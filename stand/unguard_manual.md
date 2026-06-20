# 🛡️ Руководство по Unguard-Light: Архитектура, Уязвимости и Развертывание

Это руководство поможет понять, что такое Unguard, как он устроен "под капотом", какие в нем кроются уязвимости, и как правильно раскатывать его локально в Kubernetes.

---

## 1. Что такое Unguard?

**Unguard** — это намеренно уязвимое cloud-native микросервисное приложение, имитирующее работу Twitter. 
Оно создано для демонстрации и тренировки эксплуатации уязвимостей в распределенных микросервисных архитектурах. Приложение позволяет пользователям регистрироваться, публиковать текстовые посты, URL и изображения, ставить лайки, подписываться на других и изменять профиль.

> [!WARNING]
> Unguard содержит критические уязвимости (SQLi, RCE, SSRF и др.) **by design**. Разворачивайте его строго в локальном и изолированном окружении (Minikube / k3d / OrbStack).

---

## 2. Архитектура "под капотом"

Приложение состоит из **12 микросервисов**, написанных на разных языках, и использует **3 различные базы данных**. Все сервисы общаются между собой по REST API.

![Unguard Architecture](https://raw.githubusercontent.com/dynatrace-oss/unguard/main/docs/images/unguard-architecture.svg)

### Ключевые компоненты:
1. **Envoy Proxy**: Точка входа в кластер. Маршрутизирует внешний трафик на фронтенд или `ad-service`.
2. **Frontend (Next.js)**: Предоставляет веб-интерфейс и API Gateway для взаимодействия с другими микросервисами.
3. **Бэкенд-сервисы (Бизнес-логика)**:
   - **`microblog-service` (Java Spring)**: Основной сервис постов. Пишет данные в **Redis**.
   - **`user-auth-service` (Node.js/Express)**: Регистрация и выдача JWT-токенов.
   - **`profile-service` (Java Spring)**: Обновление биографии (использует In-Memory БД **H2**).
   - **`membership-service` (.NET 7)** и **`like-service` (PHP)**: Обрабатывают лайки и статус членства, пишут в **MariaDB**.
   - **`payment-service` (Python Flask)**: Добавление и получение данных кредитных карт.
4. **Базы данных**:
   - **MariaDB**: Реляционная БД для хранения критичных данных (пользователи, пароли, лайки).
   - **Redis**: In-Memory хранилище для ленты постов (Timeline) и микро-блогов.
   - **H2**: Временная SQL-база (только в `profile-service`).

---

## 3. Теория уязвимостей в Unguard

Вместо монолитных уязвимостей (как в Juice Shop), Unguard распределяет дыры по микросервисам:

1. **SQL Injection (SQLi)**
   - Присутствует сразу в нескольких сервисах, написанных на разных языках (`profile-service` на Java, `membership-service` на .NET, `like-service` на PHP, `user-auth-service` на Node.js).
   - *Причина*: Использование сырых конкатенаций строк при формировании SQL-запросов вместо Prepared Statements.
2. **Server-Side Request Forgery (SSRF)**
   - В `proxy-service` (Java Spring). 
   - *Причина*: Сервис проксирует запросы от фронтенда (загрузка картинок/превью) без санитаризации введённого URL, позволяя злоумышленнику стучаться во внутренние порты кластера Kubernetes.
3. **JWT Key Confusion**
   - В `user-auth-service`. 
   - *Причина*: Библиотека верификации некорректно проверяет алгоритм токена (позволяя подсунуть публичный ключ вместо симметричного секрета).
4. **Remote Code Execution (RCE) / Deserialization**
   - В `microblog-service`. 
   - *Причина*: Явное использование уязвимых версий библиотек (например, `jackson-databind 2.9.9`), что позволяет выполнить десериализацию недоверенных данных из Redis.
5. **LLM Data Poisoning**
   - В `rag-service` (Python FastAPI).
   - *Причина*: Сервис антиспама обучается на входящем фидбеке пользователей, позволяя внедрять вредоносные промпты (Prompt Injection) прямо в Knowledge Base.

---

## 4. Инструкция по развертыванию

Поскольку Unguard упакован в Helm-чарты, развертывание в локальном Kubernetes (OrbStack/Minikube) производится в два шага.

### Шаг 1: Подготовка окружения и установка БД
Unguard зависит от MariaDB. В официальном чарте база вынесена в зависимость от Bitnami.

```bash
# 1. Добавляем репозиторий Bitnami
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# 2. Создаем namespace
kubectl create namespace unguard

# 3. Устанавливаем MariaDB
helm install unguard-mariadb bitnami/mariadb \
  --version 11.5.7 \
  --set primary.persistence.enabled=false \
  --wait \
  --namespace unguard
```
> [!NOTE]
> Флаг `--set primary.persistence.enabled=false` отключает создание постоянных томов (PVC), что идеально для локального стенда — база будет полностью очищаться при удалении пода.

### Шаг 2: Установка Unguard
Теперь раскатываем сами микросервисы из скачанной директории `chart/`.

```bash
# Переходим в директорию с проектом
cd /Users/mac/Desktop/sacner/stand/unguard-light

# Устанавливаем локальный чарт
helm install unguard ./chart \
  --wait \
  --namespace unguard
```

### Шаг 3: Доступ к приложению
По умолчанию локальный чарт разворачивает Ingress-контроллер, но для гарантированного доступа (если Ingress не настроен) можно просто прокинуть порт `envoy-proxy`:

```bash
kubectl port-forward svc/unguard-envoy-proxy -n unguard 8080:8080
```
Приложение будет доступно по адресу: **`http://localhost:8080`**.

---

## 5. Дополнительные фичи (Опционально)

Если нужно включить генератор трафика (ботов, которые постят и лайкают) или RAG-сервис (LLM-спам-фильтр), можно применить кастомные `values.yaml` при установке чарта:

```bash
helm upgrade --install unguard ./chart \
  --namespace unguard \
  --set maliciousLoadGenerator.enabled=true \
  --set ragService.enabled=true \
  --set ollama.enabled=true
```
