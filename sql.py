import aiohttp
import asyncio
import json
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_time_based_sql_injection(session, url, data, expected_delay=5):
    payloads = [
        "';WAITFOR DELAY '0:0:5';--",
        "';WAITFOR DELAY '0:0:10';--",
        "';WAITFOR DELAY '0:0:15';--",
    ]
    for payload in payloads:
        injected_data = {k: v + payload for k, v in data.items()}
        logger.info(f"Testing time-based SQL injection with payload: {payload}")
        start_time = time.time()
        async with session.post(url, data=injected_data) as response:
            await response.text()
        response_time = time.time() - start_time
        if response_time >= expected_delay:
            return {
                'url': url,
                'parameter': injected_data,
                'payload': payload,
                'method': 'POST',
                'vulnerable': True,
                'response_time': response_time,
                'is_vulnerable': True,
                'type': 'Time-based',
                'description': "Time-based SQL-инъекция использует задержки во времени ответа для выявления уязвимостей.",
                'risk_level': "🔴 Высокий",
                'recommendation': (
                    "Для предотвращения Time-based SQL-инъекций рекомендуется:\n"
                    "1. Использовать подготовленные выражения (prepared statements) и параметризованные запросы.\n"
                    "   Пример для Python с использованием SQLite:\n"
                    "   ```python\n"
                    "   import sqlite3\n"
                    "   conn = sqlite3.connect('example.db')\n"
                    "   cursor = conn.cursor()\n"
                    "   cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
                    "   ```\n"
                    "2. Проверять и фильтровать все входные данные, используя валидацию и экранирование.\n"
                    "3. Использовать ORM (Object-Relational Mapping) для взаимодействия с базой данных.\n"
                    "   Пример для SQLAlchemy:\n"
                    "   ```python\n"
                    "   from sqlalchemy import create_engine\n"
                    "   from sqlalchemy.orm import sessionmaker\n"
                    "   engine = create_engine('sqlite:///example.db')\n"
                    "   Session = sessionmaker(bind=engine)\n"
                    "   session = Session()\n"
                    "   user = session.query(User).filter(User.id == user_id).first()\n"
                    "   ```\n"
                    "4. Ограничить права доступа к базе данных для веб-приложения.\n"
                    "5. Регулярно обновлять и патчить используемое ПО.\n"
                    "6. Использовать инструменты для динамического анализа безопасности (DAST) и статического анализа безопасности (SAST).\n"
                    "Для получения дополнительной информации, посетите [OWASP Time-based SQL Injection](https://owasp.org/www-community/attacks/Time_based_SQL_Injection)."
                )
            }
    return {'url': url, 'is_vulnerable': False}

async def test_blind_sql_injection(session, url, data):
    true_payloads = [
        "' OR 1=1--",
        "' OR '1'='1'--",
        "' OR 1=1#",
    ]
    false_payloads = [
        "' OR 1=2--",
        "' OR '1'='2'--",
        "' OR 1=2#",
    ]
    for true_payload, false_payload in zip(true_payloads, false_payloads):
        injected_data_true = {k: v + true_payload for k, v in data.items()}
        injected_data_false = {k: v + false_payload for k, v in data.items()}

        async with session.post(url, data=injected_data_true) as response_true, session.post(url, data=injected_data_false) as response_false:
            text_true = await response_true.text()
            text_false = await response_false.text()

            if text_true != text_false:
                return {
                    'url': url,
                    'parameter': injected_data_true,
                    'payload': true_payload,
                    'method': 'POST',
                    'vulnerable': True,
                    'is_vulnerable': True,
                    'type': 'Blind',
                    'description': "Blind SQL-инъекция позволяет определять наличие уязвимостей без вывода ошибок.",
                    'risk_level': "🔴 Высокий",
                    'recommendation': (
                        "Для предотвращения Blind SQL-инъекций рекомендуется:\n"
                        "1. Использовать подготовленные выражения (prepared statements) и параметризованные запросы.\n"
                        "   Пример для Python с использованием SQLite:\n"
                        "   ```python\n"
                        "   import sqlite3\n"
                        "   conn = sqlite3.connect('example.db')\n"
                        "   cursor = conn.cursor()\n"
                        "   cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
                        "   ```\n"
                        "2. Проверять и фильтровать все входные данные, используя валидацию и экранирование.\n"
                        "3. Использовать ORM (Object-Relational Mapping) для взаимодействия с базой данных.\n"
                        "   Пример для SQLAlchemy:\n"
                        "   ```python\n"
                        "   from sqlalchemy import create_engine\n"
                        "   from sqlalchemy.orm import sessionmaker\n"
                        "   engine = create_engine('sqlite:///example.db')\n"
                        "   Session = sessionmaker(bind=engine)\n"
                        "   session = Session()\n"
                        "   user = session.query(User).filter(User.id == user_id).first()\n"
                        "   ```\n"
                        "4. Ограничить права доступа к базе данных для веб-приложения.\n"
                        "5. Регулярно обновлять и патчить используемое ПО.\n"
                        "6. Использовать инструменты для динамического анализа безопасности (DAST) и статического анализа безопасности (SAST).\n"
                        "Для получения дополнительной информации, посетите [OWASP Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)."
                    )
                }
    return {'url': url, 'is_vulnerable': False}

async def test_error_based_sql_injection(session, url, data):
    payloads = [
        "' OR 1=1--",
        "' OR 'a'='a'--",
        "' OR 1=1#",
        "' OR 'a'='a'#",
    ]
    for payload in payloads:
        injected_data = {k: v + payload for k, v in data.items()}
        logger.info(f"Testing error-based SQL injection with payload: {payload}")
        async with session.post(url, data=injected_data) as response:
            text = await response.text()
            if "error" in text.lower() or "sql" in text.lower():
                return {
                    'url': url,
                    'parameter': injected_data,
                    'payload': payload,
                    'method': 'POST',
                    'vulnerable': True,
                    'is_vulnerable': True,
                    'type': 'Error-based',
                    'description': "Error-based SQL-инъекция использует сообщения об ошибках для получения данных.",
                    'risk_level': "🔴 Высокий",
                    'recommendation': (
                        "Для предотвращения Error-based SQL-инъекций рекомендуется:\n"
                        "1. Использовать подготовленные выражения (prepared statements) и параметризованные запросы.\n"
                        "   Пример для Python с использованием SQLite:\n"
                        "   ```python\n"
                        "   import sqlite3\n"
                        "   conn = sqlite3.connect('example.db')\n"
                        "   cursor = conn.cursor()\n"
                        "   cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
                        "   ```\n"
                        "2. Проверять и фильтровать все входные данные, используя валидацию и экранирование.\n"
                        "3. Использовать ORM (Object-Relational Mapping) для взаимодействия с базой данных.\n"
                        "   Пример для SQLAlchemy:\n"
                        "   ```python\n"
                        "   from sqlalchemy import create_engine\n"
                        "   from sqlalchemy.orm import sessionmaker\n"
                        "   engine = create_engine('sqlite:///example.db')\n"
                        "   Session = sessionmaker(bind=engine)\n"
                        "   session = Session()\n"
                        "   user = session.query(User).filter(User.id == user_id).first()\n"
                        "   ```\n"
                        "4. Ограничить права доступа к базе данных для веб-приложения.\n"
                        "5. Регулярно обновлять и патчить используемое ПО.\n"
                        "6. Использовать инструменты для динамического анализа безопасности (DAST) и статического анализа безопасности (SAST).\n"
                        "Для получения дополнительной информации, посетите [OWASP Error-based SQL Injection](https://owasp.org/www-community/attacks/Error_based_SQL_Injection)."
                    )
                }
    return {'url': url, 'is_vulnerable': False}

async def test_union_based_sql_injection(session, url, data):
    payloads = [
        "' UNION SELECT null--",
        "' UNION SELECT null, null--",
        "' UNION SELECT null, null, null--",
    ]
    for payload in payloads:
        injected_data = {k: v + payload for k, v in data.items()}
        logger.info(f"Testing union-based SQL injection with payload: {payload}")
        async with session.post(url, data=injected_data) as response:
            text = await response.text()
            if "error" not in text.lower() and "sql" not in text.lower():
                return {
                    'url': url,
                    'parameter': injected_data,
                    'payload': payload,
                    'method': 'POST',
                    'vulnerable': True,
                    'is_vulnerable': True,
                    'type': 'Union-based',
                    'description': "Union-based SQL-инъекция позволяет объединять результаты нескольких запросов.",
                    'risk_level': "🔴 Высокий",
                    'recommendation': (
                        "Для предотвращения Union-based SQL-инъекций рекомендуется:\n"
                        "1. Использовать подготовленные выражения (prepared statements) и параметризованные запросы.\n"
                        "   Пример для Python с использованием SQLite:\n"
                        "   ```python\n"
                        "   import sqlite3\n"
                        "   conn = sqlite3.connect('example.db')\n"
                        "   cursor = conn.cursor()\n"
                        "   cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
                        "   ```\n"
                        "2. Проверять и фильтровать все входные данные, используя валидацию и экранирование.\n"
                        "3. Использовать ORM (Object-Relational Mapping) для взаимодействия с базой данных.\n"
                        "   Пример для SQLAlchemy:\n"
                        "   ```python\n"
                        "   from sqlalchemy import create_engine\n"
                        "   from sqlalchemy.orm import sessionmaker\n"
                        "   engine = create_engine('sqlite:///example.db')\n"
                        "   Session = sessionmaker(bind=engine)\n"
                        "   session = Session()\n"
                        "   user = session.query(User).filter(User.id == user_id).first()\n"
                        "   ```\n"
                        "4. Ограничить права доступа к базе данных для веб-приложения.\n"
                        "5. Регулярно обновлять и патчить используемое ПО.\n"
                        "6. Использовать инструменты для динамического анализа безопасности (DAST) и статического анализа безопасности (SAST).\n"
                        "Для получения дополнительной информации, посетите [OWASP Union-based SQL Injection](https://owasp.org/www-community/attacks/Union_SQL_Injection)."
                    )
                }
    return {'url': url, 'is_vulnerable': False}

async def analyze_vulnerabilities(data):
    vulnerabilities = []
    async with aiohttp.ClientSession() as session:
        for entry in data:
            url = entry['URL']
            for form in entry.get('Forms', []):
                form_action = form.get('action')
                form_method = form.get('method', 'GET').upper()
                form_inputs = form.get('inputs', [])
                form_data = {input_tag['name']: input_tag.get('value', '') for input_tag in form_inputs if input_tag['type'] != 'submit'}

                if form_method == 'POST':
                    vulnerability = await test_error_based_sql_injection(session, form_action, form_data)
                    if vulnerability['is_vulnerable']:
                        vulnerabilities.append(vulnerability)

                    vulnerability = await test_union_based_sql_injection(session, form_action, form_data)
                    if vulnerability['is_vulnerable']:
                        vulnerabilities.append(vulnerability)

                    vulnerability = await test_time_based_sql_injection(session, form_action, form_data)
                    if vulnerability['is_vulnerable']:
                        vulnerabilities.append(vulnerability)

                    vulnerability = await test_blind_sql_injection(session, form_action, form_data)
                    if vulnerability['is_vulnerable']:
                        vulnerabilities.append(vulnerability)
    return vulnerabilities

def load_scraped_data(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)
