def get_sql_injection_recommendation():
    return (
        "Для предотвращения SQL-инъекций рекомендуется:\n"
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
        "Для получения дополнительной информации, посетите [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)."
    )

def get_xss_recommendation():
    return (
        "Для предотвращения XSS-атак рекомендуется:\n"
        "1. Правильно экранировать все данные, выводимые на страницу.\n"
        "   Пример для JavaScript:\n"
        "   ```javascript\n"
        "   function escapeHtml(unsafe) {\n"
        "       return unsafe.replace(/[&<\"']/g, function (match) {\n"
        "           const escape = {\n"
        "               '&': '&amp;',\n"
        "               '<': '&lt;',\n"
        "               '>': '&gt;',\n"
        "               '\"': '&quot;',\n"
        "               \"'\": '&#039;'\n"
        "           };\n"
        "           return escape[match];\n"
        "       });\n"
        "   }\n"
        "   ```\n"
        "2. Использовать функции и библиотеки для экранирования HTML (например, `htmlspecialchars` в PHP).\n"
        "3. Проверять и фильтровать все входные данные.\n"
        "4. Использовать Content Security Policy (CSP) для ограничения выполнения скриптов.\n"
        "   Пример политики CSP:\n"
        "   ```http\n"
        "   Content-Security-Policy: default-src 'self'; script-src 'self' https://trustedscripts.example.com\n"
        "   ```\n"
        "5. Избегать использования опасных JavaScript-функций, таких как `eval`.\n"
        "6. Регулярно проводить тестирование безопасности и использовать автоматизированные инструменты для проверки на XSS.\n"
        "Для получения дополнительной информации, посетите [OWASP XSS](https://owasp.org/www-community/attacks/xss/)."
    )

def get_error_based_sql_injection_recommendation():
    return (
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

def get_time_based_sql_injection_recommendation():
    return (
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
def get_csrf_recommendation():
    return (
        "Для предотвращения CSRF-атак рекомендуется:\n"
        "1. Использовать уникальные CSRF-токены для каждой сессии и каждого запроса.\n"
        "2. Проверять наличие и корректность CSRF-токенов на сервере.\n"
        "3. Использовать SameSite флаг для cookie, чтобы ограничить их использование сторонними сайтами.\n"
        "4. Ограничивать допустимые источники запросов с помощью CORS (Cross-Origin Resource Sharing).\n"
        "Для получения дополнительной информации, посетите [OWASP CSRF](https://owasp.org/www-community/attacks/csrf)."
    )

def get_lfi_recommendation():
    return (
        "Для предотвращения LFI-атак рекомендуется:\n"
        "1. Проверять и фильтровать все входные данные, особенно параметры пути файлов.\n"
        "2. Использовать безопасные функции для включения файлов, такие как realpath() и basename().\n"
        "3. Ограничить доступ к файловой системе на уровне веб-сервера и приложения.\n"
        "4. Регулярно обновлять и патчить используемое ПО.\n"
        "Для получения дополнительной информации, посетите [OWASP LFI](https://owasp.org/www-community/attacks/Path_Traversal)."
    )

def get_rfi_recommendation():
    return (
        "Для предотвращения RFI-атак рекомендуется:\n"
        "1. Отключить возможность включения удаленных файлов в настройках PHP (allow_url_include=Off).\n"
        "2. Проверять и фильтровать все входные данные, особенно параметры пути файлов.\n"
        "3. Использовать безопасные функции для включения файлов, такие как realpath() и basename().\n"
        "4. Регулярно обновлять и патчить используемое ПО.\n"
        "Для получения дополнительной информации, посетите [OWASP RFI](https://owasp.org/www-community/attacks/Remote_File_Inclusion)."
    )

def get_idor_recommendation():
    return (
        "Для предотвращения IDOR-атак рекомендуется:\n"
        "1. Использовать контроль доступа на сервере для проверки прав доступа пользователей к объектам.\n"
        "2. Избегать использования предсказуемых идентификаторов объектов.\n"
        "3. Использовать непрямые ссылки и токены для доступа к объектам.\n"
        "4. Регулярно проводить тестирование безопасности и использовать автоматизированные инструменты для проверки на IDOR.\n"
        "Для получения дополнительной информации, посетите [OWASP IDOR](https://owasp.org/www-community/attacks/IDOR)."
    )

def generate_recommendation(vulnerability_type):
    if vulnerability_type == 'SQL Injection':
        return get_sql_injection_recommendation()
    elif vulnerability_type == 'XSS':
        return get_xss_recommendation()
    elif vulnerability_type == 'Error-based':
        return get_error_based_sql_injection_recommendation()
    elif vulnerability_type == 'Time-based':
        return get_time_based_sql_injection_recommendation()
    elif vulnerability_type == 'CSRF':
        return get_csrf_recommendation()
    elif vulnerability_type == 'LFI':
        return get_lfi_recommendation()
    elif vulnerability_type == 'RFI':
        return get_rfi_recommendation()
    elif vulnerability_type == 'IDOR':
        return get_idor_recommendation()
    else:
        return "Рекомендация для данной уязвимости не найдена."
