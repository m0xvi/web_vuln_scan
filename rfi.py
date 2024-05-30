import asyncio
import aiohttp
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_rfi(session, base_url, param):
    rfi_payloads = [
        'https://raw.githubusercontent.com/your-username/your-repo/main/rfi_test.txt',
        'https://raw.githubusercontent.com/m0xvi/web_vuln_scan/master/test/lfi_rfi_test/rfi',
    ]
    for payload in rfi_payloads:
        # Формируем URL правильно, заменяя значение параметра
        payloaded_url = f"{base_url.split('?')[0]}?{param}={payload}"
        logger.info(f"Testing RFI with URL: {payloaded_url}")
        try:
            response = await session.get(payloaded_url)
            response_text = await response.text()
            logger.info(f"Response for {payloaded_url}: {response_text[:100]}")  # Логируем первые 100 символов ответа
            # Проверка на наличие ожидаемого содержимого
            if 'This is a test file for RFI' in response_text:
                logger.info(f"RFI vulnerability found: {payloaded_url}")
                return True, payloaded_url
        except Exception as e:
            logger.error(f"Error testing RFI payload on {base_url}: {e}")
    return False, None

async def analyze_rfi(scraped_data):
    vulnerabilities = []
    async with aiohttp.ClientSession() as session:
        for page in scraped_data:
            url = page['URL']
            params = page.get('Parameters', {})
            for param in params:
                logger.info(f"Analyzing URL: {url} with param: {param}")
                is_vulnerable, vulnerable_url = await test_rfi(session, url, param)
                if is_vulnerable:
                    vulnerabilities.append({
                        'url': url,
                        'parameter': param,
                        'is_vulnerable': True,
                        'type': 'RFI',
                        'payload': vulnerable_url,
                        'description': (
                            "RFI (Remote File Inclusion) уязвимость позволяет злоумышленнику включать удаленные файлы на сервере, "
                            "используя параметры URL, что может привести к выполнению произвольного кода."
                        ),
                        'risk_level': "🔴 Высокий",
                        'recommendation': (
                            "Для предотвращения RFI атак рекомендуется:\n"
                            "1. Проверять и фильтровать все входные данные, исключая использование удаленных путей.\n"
                            "2. Использовать белые списки допустимых значений для параметров, связанных с файлами.\n"
                            "3. Отключить функции включения файлов из удаленных источников, если они не используются.\n"
                            "4. Регулярно обновлять и патчить ПО.\n"
                        ),
                        'code_examples': {
                            'python': (
                                "python\n"
                                "# Пример для Python с использованием белого списка разрешенных URL\n\n"
                                "from flask import Flask, request, abort\n\n"
                                "app = Flask(__name__)\n\n"
                                "# Список разрешенных URL\n"
                                "allowed_urls = ['https://example.com/test.html']\n\n"
                                "@app.route('/include')\n"
                                "def include_url():\n"
                                "    url = request.args.get('url')\n"
                                "    if url not in allowed_urls:\n"
                                "        abort(400)\n"
                                "    response = requests.get(url)\n"
                                "    return response.text\n\n"
                                "if __name__ == '__main__':\n"
                                "    app.run()"
                            ),
                            'php': (
                                "php\n"
                                "<?php\n"
                                "// Пример для PHP с использованием белого списка разрешенных URL\n\n"
                                "// Список разрешенных URL\n"
                                "$allowed_urls = ['https://example.com/test.php'];\n\n"
                                "if (isset($_GET['url']) && in_array($_GET['url'], $allowed_urls)) {\n"
                                "  include $_GET['url'];\n"
                                "} else {\n"
                                "  echo 'Недопустимый URL';\n"
                                "}\n"
                                "?>"
                            ),
                            'java': (
                                "java\n"
                                "import java.io.IOException;\n"
                                "import java.net.HttpURLConnection;\n"
                                "import java.net.URL;\n"
                                "import java.util.Arrays;\n"
                                "import java.util.List;\n"
                                "import javax.servlet.ServletException;\n"
                                "import javax.servlet.annotation.WebServlet;\n"
                                "import javax.servlet.http.HttpServlet;\n"
                                "import javax.servlet.http.HttpServletRequest;\n"
                                "import javax.servlet.http.HttpServletResponse;\n\n"
                                "@WebServlet(\"/include\")\n"
                                "public class IncludeServlet extends HttpServlet {\n"
                                "    private static final List<String> allowedUrls = Arrays.asList(\"https://example.com/test.jsp\");\n\n"
                                "    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {\n"
                                "        String urlString = request.getParameter(\"url\");\n"
                                "        if (urlString == null || !allowedUrls.contains(urlString)) {\n"
                                "            response.sendError(HttpServletResponse.SC_BAD_REQUEST, \"Недопустимый URL\");\n"
                                "            return;\n"
                                "        }\n"
                                "        URL url = new URL(urlString);\n"
                                "        HttpURLConnection conn = (HttpURLConnection) url.openConnection();\n"
                                "        conn.setRequestMethod(\"GET\");\n"
                                "        conn.connect();\n"
                                "        InputStream in = conn.getInputStream();\n"
                                "        byte[] buffer = new byte[1024];\n"
                                "        int bytesRead;\n"
                                "        while ((bytesRead = in.read(buffer)) != -1) {\n"
                                "            response.getOutputStream().write(buffer, 0, bytesRead);\n"
                                "        }\n"
                                "    }\n"
                                "}"
                            ),
                            'javascript': (
                                "javascript\n"
                                "// Пример для Node.js с использованием белого списка разрешенных URL\n\n"
                                "const express = require('express');\n"
                                "const axios = require('axios');\n\n"
                                "const app = express();\n\n"
                                "const allowedUrls = ['https://example.com/test.html'];\n\n"
                                "app.get('/include', async (req, res) => {\n"
                                "    const url = req.query.url;\n"
                                "    if (!allowedUrls.includes(url)) {\n"
                                "        return res.status(400).send('Недопустимый URL');\n"
                                "    }\n"
                                "    try {\n"
                                "        const response = await axios.get(url);\n"
                                "        res.send(response.data);\n"
                                "    } catch (error) {\n"
                                "        res.status(500).send('Ошибка при получении данных');\n"
                                "    }\n"
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
    vulnerabilities = asyncio.run(analyze_rfi(scraped_data))
    with open('rfi_vulnerabilities.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
