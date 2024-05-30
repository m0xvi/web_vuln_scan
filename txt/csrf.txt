import logging
import json
import asyncio
import aiohttp
from bs4 import BeautifulSoup

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def test_csrf(session, url, form):
    form_data = {input['name']: input['value'] for input in form['inputs'] if input['name']}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    response = await session.post(url, data=form_data, headers=headers)
    logger.info(f"Tested CSRF for URL: {url} - Status Code: {response.status}")
    return response.status != 403


async def analyze_csrf(scraped_data):
    vulnerabilities = []
    async with aiohttp.ClientSession() as session:
        for page in scraped_data:
            url = page['URL']
            forms = page.get('Forms', [])
            logger.info(f"Analyzing URL: {url} - Found Forms: {len(forms)}")
            for form in forms:
                if await test_csrf(session, url, form):
                    form_fields = [input['name'] for input in form['inputs'] if input['name']]
                    vulnerabilities.append({
                        'url': url,
                        'form_action': form['action'],
                        'form_method': form['method'],
                        'form_fields': form_fields,
                        'is_vulnerable': True,
                        'type': 'CSRF',
                        'description': (
                            "CSRF уязвимость позволяет злоумышленнику заставить пользователя выполнить "
                            "нежелательное действие на сайте, на котором он авторизован."
                        ),
                        'risk_level': "🟠 Средний",
                        'recommendation': (
                            "Для предотвращения CSRF атак рекомендуется:\n"
                            "1. Использовать уникальные CSRF-токены для каждой формы.\n"
                            "2. Проверять наличие и валидность CSRF-токена при обработке формы на сервере.\n"
                            "3. Ограничить время жизни CSRF-токена.\n"
                            "4. Использовать заголовок 'SameSite' для cookie с значением 'Strict' или 'Lax'.\n"
                            "5. Проверять источник запроса, сравнивая значение заголовка 'Origin' или 'Referer' с доверенными доменами."
                            "Для получения дополнительной информации, посетите [Cross Site Request Forgery (CSRF)] https://owasp.org/www-community/attacks/csrf"
                        ),
                        'code_examples': {
                            'python': (
                                "python\n"
                                "# Пример для Python с использованием Flask и CSRF-токенов\n\n"
                                "from flask import Flask, request, session, make_response\n"
                                "import os\n\n"
                                "app = Flask(__name__)\n"
                                "app.secret_key = os.urandom(24)\n\n"
                                "@app.before_request\n"
                                "def csrf_protect():\n"
                                "    if request.method == 'POST':\n"
                                "        token = session.pop('_csrf_token', None)\n"
                                "        if not token or token != request.form.get('_csrf_token'):\n"
                                "            return 'CSRF token missing or incorrect', 400\n\n"
                                "def generate_csrf_token():\n"
                                "    token = os.urandom(24).hex()\n"
                                "    session['_csrf_token'] = token\n"
                                "    return token\n\n"
                                "app.jinja_env.globals['csrf_token'] = generate_csrf_token\n\n"
                                "@app.route('/')\n"
                                "def index():\n"
                                "    resp = make_response('Setting a cookie')\n"
                                "    resp.set_cookie('example', 'value', samesite='Strict')\n"
                                "    return resp\n\n"
                                "if __name__ == '__main__':\n"
                                "    app.run()"
                            ),
                            'php': (
                                "php\n"
                                "<?php\n"
                                "// Пример для PHP с использованием SameSite и CSRF-токена\n\n"
                                "// Установка cookie с параметром SameSite\n"
                                "setcookie('example', 'value', [\n"
                                "  'samesite' => 'Strict',\n"
                                "  'secure' => true,\n"
                                "  'httponly' => true\n"
                                "]);\n\n"
                                "// Генерация и проверка CSRF-токена\n"
                                "session_start();\n"
                                "if ($_SERVER['REQUEST_METHOD'] === 'POST') {\n"
                                "  if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {\n"
                                "    die('Invalid CSRF token');\n"
                                "  }\n"
                                "}\n"
                                "$_SESSION['csrf_token'] = bin2hex(random_bytes(32));\n"
                                "?>\n\n"
                                "<form method=\"POST\">\n"
                                "  <input type=\"hidden\" name=\"csrf_token\" value=\"<?php echo $_SESSION['csrf_token']; ?>\">\n"
                                "  <!-- Остальные поля формы -->\n"
                                "</form>"
                            ),
                            'java': (
                                "// Пример для Java с использованием Spring Security и CSRF\n\n"
                                "import org.springframework.context.annotation.Configuration;\n"
                                "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\n"
                                "import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;\n"
                                "import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;\n\n"
                                "@Configuration\n"
                                "@EnableWebSecurity\n"
                                "public class SecurityConfig extends WebSecurityConfigurerAdapter {\n"
                                "    @Override\n"
                                "    protected void configure(HttpSecurity http) throws Exception {\n"
                                "        http\n"
                                "            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())\n"
                                "            .and()\n"
                                "            .authorizeRequests()\n"
                                "            .anyRequest().authenticated();\n"
                                "    }\n"
                                "}"
                            ),
                            'javascript': (
                                "javascript\n"
                                "// Пример для Node.js с использованием Express и CSRF-токенов\n\n"
                                "const express = require('express');\n"
                                "const csrf = require('csurf');\n"
                                "const cookieParser = require('cookie-parser');\n\n"
                                "const app = express();\n"
                                "const csrfProtection = csrf({ cookie: true });\n\n"
                                "app.use(cookieParser());\n\n"
                                "app.get('/form', csrfProtection, (req, res) => {\n"
                                "    res.cookie('example', 'value', { sameSite: 'Strict' });\n"
                                "    res.send(`\n"
                                "        <form action=\"/process\" method=\"POST\">\n"
                                "            <input type=\"hidden\" name=\"_csrf\" value=\"${req.csrfToken()}\">\n"
                                "            <!-- Остальные поля формы -->\n"
                                "            <button type=\"submit\">Submit</button>\n"
                                "        </form>\n"
                                "    `);\n"
                                "});\n\n"
                                "app.post('/process', csrfProtection, (req, res) => {\n"
                                "    res.send('Форма успешно отправлена');\n"
                                "});\n\n"
                                "app.listen(3000, () => console.log('Server is running on port 3000'));"
                            )
                        }
                    })
    return vulnerabilities


def load_scraped_data(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        logger.info(f"Scraped data loaded from {file_path}")
        return data
    except Exception as e:
        logger.error(f"Error loading scraped data from {file_path}: {e}")
        return []


if __name__ == '__main__':
    scraped_data = load_scraped_data('scraped_data.json')
    vulnerabilities = asyncio.run(analyze_csrf(scraped_data))
    with open('csrf_vulnerabilities.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
    print("CSRF Scan Results:", json.dumps(vulnerabilities, indent=4))
