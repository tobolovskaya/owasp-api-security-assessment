# Звіт з виявлення та аналізу вразливостей у REST API OWASP Juice Shop

**Виконав:** Тоболовська Євгенія    
**Курс:** Secure Software Development and Integration

---

## 📋 Зміст

1. [Вступ](#вступ)
2. [Таблиця виявлених вразливостей](#таблиця-виявлених-вразливостей)
3. [Детальний аналіз вразливостей](#детальний-аналіз-вразливостей)
4. [Відповідність STRIDE та CWE](#відповідність-stride-та-cwe)
5. [Рекомендації щодо захисту](#рекомендації-щодо-захисту)
6. [Висновки](#висновки)


---

## Вступ

У рамках лабораторної роботи було проведено аналіз безпеки REST API застосунку OWASP Juice Shop з метою виявлення типових вразливостей, що зустрічаються в сучасних вебзастосунках. 

**Використані інструменти:**
- **Docker** для розгортання OWASP Juice Shop (`bkimminich/juice-shop`)
- **Postman** для тестування API endpoints
- **jwt.io** для аналізу JWT токенів

**Методологія:**
Тестування проводилося відповідно до методології OWASP API Security Top 10 (2023) з використанням threat modeling підходів STRIDE та класифікації вразливостей за CWE.

---

## Таблиця виявлених вразливостей

| № | Ендпоінт | Метод | Токен? | Уразливість | OWASP API | STRIDE | CWE |
|---|----------|-------|--------|-------------|-----------|--------|-----|
| 1 | `/rest/user/login` | POST | Ні | Information Disclosure (Password Hash in JWT) | A03 | Information Disclosure | CWE-200 |
| 2 | `/api/Users` | GET | Так | Broken Function Level Authorization | A05 | Elevation of Privilege | CWE-285 |
| 3 | `/rest/basket/7` | GET | Так | IDOR (Broken Object Level Authorization) | A01 | Elevation of Privilege | CWE-639 |
| 4 | `/api/Users` | POST | Ні | Mass Assignment | A06 | Elevation of Privilege | CWE-915 |
| 5 | `/rest/products/search` | GET | Ні | SQL Injection | A10 | Tampering | CWE-89 |

---

## Детальний аналіз вразливостей

### 🔴 Вразливість №1: Information Disclosure (Password Hash in JWT)

**Ендпоінт:** `POST /rest/user/login`

#### Суть проблеми

При автентифікації користувача застосунок повертає JWT токен, який містить **повний об'єкт користувача**, включаючи хеш пароля:

```json
{
  "id": 23,
  "email": "student@example.com",
  "password": "048fe686fd7f8cad6e4d9ac6e400c120",  // ❌ MD5 hash
  "role": "customer",
  "totpSecret": "",
  "profileImage": "/assets/public/images/uploads/default.svg"
}
```

#### Чому це небезпечно

1. **Витік хешу пароля:** Будь-хто, хто перехопить JWT (наприклад, через XSS або MITM), отримує доступ до хешу пароля
2. **Слабкий алгоритм:** MD5 легко зламати через rainbow tables або brute force
3. **Порушення Principle of Least Privilege:** JWT містить надлишкові дані (profileImage, totpSecret, timestamps), які не потрібні для авторизації
4. **Репутаційні ризики:** Порушення GDPR (Article 32 - Security of processing)

#### Заходи захисту

**1. Мінімізація JWT payload:**
```json
{
  "sub": "23",
  "email": "student@example.com",
  "role": "customer",
  "exp": 1721163000,
  "iat": 1721159400
}
```

**2. Використання bcrypt замість MD5:**
```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
hashed_password = pwd_context.hash(plain_password)
```

**3. Secure token storage:**
- Зберігати JWT в `HttpOnly` cookies замість localStorage
- Використовувати короткоживучі access tokens (5-15 хв) + refresh tokens

---

### 🔴 Вразливість №2: Broken Function Level Authorization

**Ендпоінт:** `GET /api/Users`

#### Суть проблеми

Endpoint `/api/Users` повертає список **всіх користувачів** системи, включаючи адміністратора (`admin@juice-sh.op`), навіть коли запит виконується від імені звичайного користувача з роллю `customer`.

**Запит:**
```http
GET /api/Users HTTP/1.1
Authorization: Bearer <токен_звичайного_користувача>
```

**Відповідь:**
```json
{
  "data": [
    {
      "id": 1,
      "email": "admin@juice-sh.op",
      "role": "admin"
    },
    {
      "id": 2,
      "email": "jim@juice-sh.op"
    }
    // ... всі користувачі
  ]
}
```

#### Чому це небезпечно

1. **Витік інформації про структуру системи:** Зловмисник дізнається email адміністратора
2. **Підготовка до targeted attacks:** Email `admin@juice-sh.op` можна використати для phishing або brute force
3. **Порушення конфіденційності:** Звичайні користувачі бачать особисті дані інших користувачів
4. **Ескалація прав:** Відсутність RBAC дозволяє виконувати admin-функції без admin-ролі

#### Заходи захисту

**1. Перевірка ролі через декоратор (з курсу):**
```python
from functools import wraps
from fastapi import HTTPException

def require_role(required_role: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: User, **kwargs):
            if current_user.role != required_role:
                raise HTTPException(
                    status_code=403,
                    detail=f"Requires {required_role} role"
                )
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

@app.get("/api/Users")
@require_role("admin")
async def get_users(current_user: User = Depends(get_current_user)):
    return db.all_users()
```

**2. Використання OPA (Open Policy Agent):**
```rego
package api.authz

default allow = false

allow {
    input.method == "GET"
    input.path == ["api", "Users"]
    input.user.role == "admin"
}
```

**3. API Gateway rules (Kong/AWS API Gateway):**
```yaml
policies:
  - name: rbac-check
    config:
      roles:
        - admin
      endpoint: /api/Users
```

---

### 🔴 Вразливість №3: IDOR (Insecure Direct Object Reference)

**Ендпоінт:** `GET /rest/basket/{id}`

#### Суть проблеми

Endpoint дозволяє отримати кошик **будь-якого користувача** шляхом підміни параметра `id` у URL, без перевірки ownership.

**Сценарій атаки:**
1. Користувач №1 (id=23) отримує свій токен
2. Користувач №1 змінює URL: `/rest/basket/1` → `/rest/basket/7`
3. API повертає кошик користувача №7 (UserId=24)

**Запит:**
```http
GET /rest/basket/7 HTTP/1.1
Authorization: Bearer <токен_користувача_23>
```

**Відповідь:**
```json
{
  "status": "success",
  "data": {
    "id": 7,
    "UserId": 24,  // ❌ Чужий кошик!
    "Products": [...]
  }
}
```

#### Чому це небезпечно

1. **Horizontal Privilege Escalation:** Користувач отримує доступ до ресурсів інших користувачів того самого рівня
2. **Порушення конфіденційності:** Можна побачити товари в кошиках інших людей, їх купівельну поведінку
3. **Потенційна модифікація:** Якщо є PUT/DELETE endpoints, можна змінити/видалити чужі замовлення
4. **Масштабування атаки:** Перебір id від 1 до 1000 дає доступ до всіх кошиків

#### Заходи захисту

**1. Перевірка ownership (найкращий підхід):**
```python
@app.get("/rest/basket/{basket_id}")
async def get_basket(
    basket_id: int,
    current_user: User = Depends(get_current_user)
):
    basket = db.get_basket(basket_id)
    
    if not basket:
        raise HTTPException(status_code=404, detail="Basket not found")
    
    # ✅ КРИТИЧНА ПЕРЕВІРКА
    if basket.user_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Access denied: This basket does not belong to you"
        )
    
    return basket
```

**2. Використання UUID замість sequential ID:**
```python
# Замість /rest/basket/7
# Використовувати /rest/basket/f47ac10b-58cc-4372-a567-0e02b2c3d479

import uuid

class Basket(Base):
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
```

**3. Scoped JWT claims:**
```json
{
  "sub": "23",
  "scopes": [
    "basket:read:own",
    "basket:write:own"
  ]
}
```

**Перевірка scope:**
```python
if "basket:read:own" not in token.scopes:
    raise HTTPException(403)
```

---

### 🔴 Вразливість №4: Mass Assignment

**Ендпоінт:** `POST /api/Users`

#### Суть проблеми

При реєстрації користувача API приймає **будь-які поля** в JSON payload, включаючи `isAdmin`, без валідації whitelist полів.

**Атака:**
```http
POST /api/Users HTTP/1.1
Content-Type: application/json

{
  "email": "attacker@example.com",
  "password": "12345678",
  "passwordRepeat": "12345678",
  "securityQuestion": {
    "id": 1,
    "answer": "dog"
  },
  "isAdmin": true  // ❌ Зловмисник додав вручну
}
```

**Очікувана поведінка вразливого коду:**
```python
# ❌ НЕБЕЗПЕЧНО
@app.post("/api/Users")
def create_user(payload: dict):
    user = User()
    for key, value in payload.items():
        setattr(user, key, value)  # Присвоює ВСІ поля!
    db.add(user)
    db.commit()
```

#### Чому це небезпечно

1. **Privilege Escalation:** Зловмисник може отримати admin права при реєстрації
2. **Bypass бізнес-логіки:** Можна встановити `balance=1000000` або `isPremium=true`
3. **Ін'єкція метаданих:** Можна змінити `createdAt`, `role`, `isVerified`
4. **GitHub 2012 incident:** Реальний кейс, коли дослідник використав Mass Assignment для доступу до Rails repo

#### Заходи захисту

**1. Pydantic з whitelist (найкращий підхід):**
```python
from pydantic import BaseModel, EmailStr, ConfigDict
from typing import Optional

class UserCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')  # ✅ Блокує зайві поля
    
    email: EmailStr
    password: str
    passwordRepeat: str
    securityQuestion: dict
    # isAdmin НЕ включено!

@app.post("/api/Users")
def create_user(payload: UserCreate):
    # Pydantic автоматично відкине "isAdmin"
    user = User(
        email=payload.email,
        password=hash_password(payload.password),
        role="customer"  # ✅ Явно встановлюємо роль
    )
    db.add(user)
    db.commit()
    return user
```

**Спроба атаки:**
```json
{
  "email": "attacker@example.com",
  "password": "12345678",
  "isAdmin": true
}
```

**Відповідь:**
```json
{
  "detail": [
    {
      "loc": ["body", "isAdmin"],
      "msg": "extra fields not permitted",
      "type": "value_error.extra"
    }
  ]
}
```

**2. Explicit field mapping (з курсу):**
```python
@app.patch("/users/{id}")
def update_user(id: int, payload: dict):
    user = db.get_user(id)
    
    # ✅ Whitelist дозволених полів
    allowed_fields = ["name", "email", "phone"]
    
    for key, value in payload.items():
        if key in allowed_fields:
            setattr(user, key, value)
    
    db.commit()
    return user
```

---

### 🔴 Вразливість №5: SQL Injection

**Ендпоінт:** `GET /rest/products/search?q=`

#### Суть проблеми

Параметр пошуку `q` напряму підставляється в SQL запит без параметризації або екранування спецсимволів.

**Атака:**
```http
GET /rest/products/search?q='))-- HTTP/1.1
```

**Передбачуваний вразливий SQL:**
```sql
SELECT * FROM products 
WHERE name LIKE '%'))--
   OR description LIKE '%'))--
```

**Результат:** Коментар `--` відсікає решту запиту, умова WHERE стає завжди true, повертаються **всі товари**.

**Більш небезпечний payload:**
```http
GET /rest/products/search?q=' UNION SELECT id,username,password,email FROM users--
```

#### Чому це небезпечно

1. **Data Exfiltration:** Можна витягнути всі дані з БД (паролі, токени, особисті дані)
2. **Модифікація даних:** `'; DROP TABLE users; --` може видалити таблиці
3. **Bypass автентифікації:** `admin' OR '1'='1` дозволяє увійти без пароля
4. **Lateral movement:** Доступ до інших таблиць через UNION SELECT
5. **OWASP Top 10 #3:** SQL Injection досі одна з найнебезпечніших вразливостей

#### Заходи захисту

**1. Параметризовані запити (найкращий підхід):**
```python
# ❌ ВРАЗЛИВО
query = f"SELECT * FROM products WHERE name LIKE '%{user_input}%'"
cursor.execute(query)

# ✅ БЕЗПЕЧНО
query = "SELECT * FROM products WHERE name LIKE %s OR description LIKE %s"
cursor.execute(query, (f'%{user_input}%', f'%{user_input}%'))
```

**2. ORM (Sequelize, SQLAlchemy, Prisma):**
```python
from sqlalchemy import or_

products = db.query(Product).filter(
    or_(
        Product.name.like(f'%{search_term}%'),
        Product.description.like(f'%{search_term}%')
    )
).all()
```

**3. Input validation:**
```python
import re

def sanitize_search_query(query: str) -> str:
    # Whitelist: тільки літери, цифри, пробіли
    if not re.match(r'^[a-zA-Z0-9\s]+$', query):
        raise HTTPException(
            status_code=400,
            detail="Invalid search query. Only alphanumeric characters allowed."
        )
    return query

@app.get("/rest/products/search")
def search_products(q: str):
    sanitized_q = sanitize_search_query(q)
    # Використовувати ORM з sanitized_q
```

**4. WAF rules (ModSecurity):**
```apache
SecRule ARGS "@detectSQLi" \
    "id:1001,\
    phase:2,\
    block,\
    msg:'SQL Injection detected'"
```

---

## Відповідність STRIDE та CWE

### 🎯 Вразливість №2: Broken Function Level Authorization

#### STRIDE: Elevation of Privilege

**Обґрунтування:**

Категорія STRIDE "Elevation of Privilege" означає, що зловмисник може **виконувати дії з більшими правами**, ніж йому дозволено. 

**У нашому випадку:**
- Звичайний користувач з роллю `customer` може викликати endpoint `/api/Users`
- Цей endpoint має бути **доступний тільки адміністраторам** (`role: admin`)
- Але через відсутність перевірки ролі, користувач **отримує привілеї admin** для цієї конкретної функції
- Результат: horizontal/vertical privilege escalation

**З курсу (документ 7 - STRIDE таблиця):**

| Категорія STRIDE | Приклад для API | Механізми зниження ризиків |
|------------------|-----------------|---------------------------|
| **Elevation of Privilege** | Користувач зможе редагувати чужий профіль | Перевірки ownership, RBAC, ACL |

**Чому саме Elevation of Privilege, а не інші категорії:**
- **НЕ Spoofing:** Користувач автентифікований валідним токеном
- **НЕ Tampering:** Дані не змінюються, лише читаються
- **НЕ Information Disclosure:** Хоча дані розкриваються, первинна проблема - в доступі до функції
- **НЕ Denial of Service:** Система не падає
- **НЕ Repudiation:** Логування не стосується проблеми

#### CWE-285: Improper Authorization

**Обґрунтування:**

**CWE-285:** "The software does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action."

**Точна відповідність:**
- Endpoint `/api/Users` **не виконує перевірку** (does not perform)
- Перевірка авторизації **має бути**, але її немає
- Ресурс (список користувачів) доступний без перевірки прав

**Інші CWE, які могли б підходити, але менш точні:**
- **CWE-862** (Missing Authorization): Теж підходить, але CWE-285 більш загальна категорія
- **CWE-287** (Improper Authentication): НЕ підходить, бо автентифікація працює
- **CWE-284** (Improper Access Control): Занадто широка категорія

**З курсу (документ 5 - таблиця зв'язку OWASP і CWE):**

| OWASP API Загроза | CWE з Top 25 | Пояснення зв'язку |
|-------------------|--------------|-------------------|
| A05 — Broken Function Level Authorization | CWE-863: Incorrect Authorization | Відсутня перевірка ролі при доступі до POST /admin/reset |

**У нашому випадку:** Аналогічна ситуація - відсутня перевірка ролі для `GET /api/Users`.

---

### 🎯 Вразливість №5: SQL Injection

#### STRIDE: Tampering

**Обґрунтування:**

Категорія STRIDE "Tampering" означає **несанкціоновану модифікацію даних** або коду через маніпуляцію вхідними параметрами.

**У нашому випадку:**
- Зловмисник вставляє SQL код через параметр `q`
- Цей код **змінює структуру SQL запиту** (tampering з запитом)
- Результат: запит виконується не так, як задумано розробником
- Потенційно можна не тільки читати, а й **модифікувати дані** через `UPDATE`, `DELETE`, `INSERT`

**Приклад tampering:**
```sql
-- Оригінальний запит
SELECT * FROM products WHERE name LIKE '%apple%'

-- Після injection
SELECT * FROM products WHERE name LIKE '%'; UPDATE products SET price=0; --
```

**З курсу (документ 7 - STRIDE таблиця):**

| Категорія STRIDE | Приклад для API | Механізми зниження ризиків |
|------------------|-----------------|---------------------------|
| **Tampering** | Можливе успішне використання isAdmin=true в тілі запиту | Валідація даних, обмеження полів |

**Чому саме Tampering:**
- **НЕ Spoofing:** Атака не підміняє ідентичність
- **НЕ Information Disclosure:** Хоча дані витікають, первинна проблема - в модифікації запиту
- **НЕ Elevation of Privilege:** Немає ескалації прав користувача
- **Можливо Tampering ТА Information Disclosure:** SQL Injection часто відноситься до обох категорій

#### CWE-89: SQL Injection

**Обґрунтування:**

**CWE-89:** "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component."

**Точна відповідність:**
- Software (Juice Shop API) **конструює SQL команду**
- Використовує **external input** (параметр `q` з HTTP запиту)
- **НЕ нейтралізує** спецсимволи (`'`, `)`, `--`, `;`)
- Результат: **модифікація SQL команди**

**Класичний приклад з CWE-89:**
```python
# Вразливий код
query = "SELECT * FROM products WHERE name = '" + user_input + "'"
cursor.execute(query)
```

**Це точно те, що відбувається в Juice Shop!**

**З курсу (документ 5 - CWE Top 25):**

| № | CWE ID | Назва слабкості | Опис |
|---|--------|-----------------|------|
| 3 | **CWE-89** | **SQL Injection** | Неконтрольоване введення значень в SQL-запит, що дозволяє змінювати або читати базу даних |

**З курсу (документ 5 - таблиця зв'язку):**

| OWASP API Загроза | CWE з Top 25 | Пояснення зв'язку та приклад |
|-------------------|--------------|------------------------------|
| A10 — Unsafe Consumption of APIs | **CWE-89: SQL Injection** | Переданий параметр в SQL без параметризації призводить до повного доступу до бази |

---

## Рекомендації щодо захисту

### 🛡️ Короткострокові заходи (Tactical - 1-2 тижні)

**Пріоритет: CRITICAL**

1. **Виправити SQL Injection:**
   - Переписати всі raw SQL запити на параметризовані
   - Використовувати ORM (Sequelize) для всіх DB operations
   - Додати WAF rules для блокування SQLi patterns

2. **Додати RBAC middleware:**
```javascript
function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

app.get('/api/Users', requireRole('admin'), getAllUsers);
```

3. **Виправити JWT payload:**
   - Видалити `password`, `totpSecret`, `profileImage` з JWT
   - Залишити тільки `sub`, `email`, `role`, `exp`, `iat`

4. **Додати ownership checks:**
```javascript
app.get('/rest/basket/:id', async (req, res) => {
  const basket = await Basket.findByPk(req.params.id);
  
  if (basket.userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  res.json(basket);
});
```

---

### 🏗️ Середньострокові заходи (Strategic - 1-3 місяці)

**Пріоритет: HIGH**

1. **Впровадити OPA (Open Policy Agent):**
```rego
package juice_shop.authz

import future.keywords.if

default allow := false

allow if {
    input.method == "GET"
    input.path == ["api", "Users"]
    input.user.role == "admin"
}

allow if {
    input.method == "GET"
    input.path == ["rest", "basket", basket_id]
    input.user.id == data.baskets[basket_id].user_id
}
```

2. **Migrate на UUID для всіх ресурсів:**
   - Замінити sequential IDs (1, 2, 3...) на UUIDs
   - Ускладнити enumeration attacks

3. **API Gateway з rate limiting:**
```yaml
# Kong configuration
plugins:
  - name: rate-limiting
    config:
      minute: 100
      policy: local
  
  - name: request-validator
    config:
      body_schema: 'json-schema.json'
```

4. **Structured logging з trace_id:**
```javascript
logger.info({
  event: 'user.accessed_endpoint',
  user_id: req.user.id,
  endpoint: req.path,
  method: req.method,
  trace_id: req.headers['x-trace-id'],
  timestamp: new Date().toISOString()
});
```

---

### 🔐 Довгострокові заходи (Transformational - 3-6 місяців)

**Пріоритет: MEDIUM**

1. **Zero Trust Architecture:**
   - Mutual TLS (mTLS) між мікросервісами
   - Service mesh (Istio/Linkerd) для east-west traffic encryption

2. **CI/CD Security Pipeline:**
```yaml
# .github/workflows/security.yml
jobs:
  security-checks:
    steps:
      - name: SAST (Semgrep)
        run: semgrep --config=auto --error .
      
      - name: Dependency Check
        run: npm audit --audit-level=high
      
      - name: DAST (OWASP ZAP)
        run: |
          docker run -t owasp/zap2docker-stable \
            zap-baseline.py -t http://localhost:3000 \
            -O openapi.json
      
      - name: Policy Check (OPA)
        run: conftest test deployment.yaml
```

3. **Security Monitoring (SIEM):**
   - Інтеграція з Elastic Security / Splunk
   - Alerts для suspicious patterns:
     - Multiple IDOR attempts
     - SQLi patterns in logs
     - Failed authorization attempts

4. **Regular Penetration Testing:**
   - Квартальні pentest external vendors
   - Bug bounty program (HackerOne/Bugcrowd)

---

## Висновки

### 📊 Підсумкова статистика

- **Виявлено вразливостей:** 5
- **Критичних (CRITICAL):** 2 (SQL Injection, IDOR)
- **Високих (HIGH):** 2 (Broken AuthZ, Mass Assignment)
- **Середніх (MEDIUM):** 1 (Info Disclosure)

### 🎯 Охоплення OWASP API Top 10

| OWASP API 2023 | Виявлено у Juice Shop |
|----------------|----------------------|
| A01: BOLA | ✅ `/rest/basket/{id}` |
| A02: Broken Authentication | ⚠️ Частково (weak JWT) |
| A03: Excessive Data Exposure | ✅ Password hash in JWT |
| A04: Resource Consumption | ❌ Не тестувалось |
| A05: Broken Function AuthZ | ✅ `/api/Users` |
| A06: Mass Assignment | ✅ `/api/Users` POST |
| A07: SSRF | ❌ Не виявлено |
| A08: Security Misconfiguration | ⚠️ Можливо (debug endpoints?) |
| A09: Inventory Management | ❌ Не виявлено |
| A10: Unsafe Consumption | ✅ SQL Injection |

### 💡 Ключові висновки

1. **Juice Shop є відмінним навчальним інструментом**, що демонструє реальні вразливості, які зустрічаються у production системах

2. **Більшість вразливостей можна було запобігти** через:
   - Використання ORM замість raw SQL
   - Впровадження RBAC middleware
   - Валідацію input через Pydantic/Joi
   - Мінімізацію JWT payload

3. **Security-by-Design підхід критично важливий:**
   - Легше додати перевірки на етапі розробки, ніж виправляти після инциденту
   - Вартість виправлення зростає експоненційно (NIST: 30-100x після deploy)

4. **Автоматизація security checks у CI/CD** запобігла б всім виявленим вразливостям:
   - Semgrep виявив би SQL injection
   - OPA/Conftest виявили б missing authorization
   - Bandit виявив би hardcoded secrets (якщо були)

### 🚀 Рекомендації для реальних проєктів

**Для розробників:**
- Завжди використовуйте ORM
- Ніколи не включайте sensitive data в JWT
- Додавайте ownership checks для всіх resource endpoints

**Для DevSecOps:**
- Впроваджуйте security gates в CI/CD
- Автоматизуйте SAST/DAST/SCA
- Моніторьте security metrics (MTTR, vulnerability density)

**Для архітекторів:**
- Проектуйте API з Zero Trust підходом
- Використовуйте API Gateway для централізованої авторизації
- Впроваджуйте observability з trace_id

---

## Використані джерела

1. OWASP API Security Top 10 (2023) - https://owasp.org/API-Security/
2. CWE Top 25 Most Dangerous Software Weaknesses - https://cwe.mitre.org/top25/
3. OWASP Juice Shop Project - https://owasp.org/www-project-juice-shop/
4. Microsoft STRIDE Threat Modeling - https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
5. Матеріали курсу SSDLC (документи 2-7)