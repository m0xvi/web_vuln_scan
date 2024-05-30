import asyncio
import aiohttp
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_lfi(session, base_url, param):
    lfi_payloads = [
        'passwd',
        'etc/passwd',
        '../../../../etc/passwd',
        '../../../../../../windows/system32/drivers/etc/hosts',
        '../../../../../../../../../../../etc/passwd',
        '../../../../../../../../../../../windows/system32/drivers/etc/hosts'
    ]
    for payload in lfi_payloads:

        payloaded_url = f"{base_url.split('?')[0]}?{param}={payload}"
        logger.info(f"Testing LFI with URL: {payloaded_url}")
        try:
            response = await session.get(payloaded_url)
            response_text = await response.text()
            logger.info(f"Response for {payloaded_url}: {response_text[:100]}")
            if 'root:' in response_text or '127.0.0.1' in response_text:
                logger.info(f"LFI vulnerability found: {payloaded_url}")
                return True, payloaded_url
        except Exception as e:
            logger.error(f"Error testing LFI payload on {base_url}: {e}")
    return False, None

async def analyze_lfi(scraped_data):
    vulnerabilities = []
    async with aiohttp.ClientSession() as session:
        for page in scraped_data:
            url = page['URL']
            params = page.get('Parameters', {})
            for param in params:
                logger.info(f"Analyzing URL: {url} with param: {param}")
                is_vulnerable, vulnerable_url = await test_lfi(session, url, param)
                if is_vulnerable:
                    vulnerabilities.append({
                        'url': url,
                        'parameter': param,
                        'is_vulnerable': True,
                        'type': 'LFI',
                        'payload': vulnerable_url,
                        'description': (
                            "LFI (Local File Inclusion) уязвимость позволяет злоумышленнику читать локальные файлы на сервере, "
                            "используя относительные пути в параметрах URL."
                        ),
                        'risk_level': "🔴 Высокий",
                        'recommendation': (
                            "Для предотвращения LFI атак рекомендуется:\n"
                            "1. Проверять и фильтровать все входные данные, исключая использование относительных путей.\n"
                            "2. Использовать белые списки допустимых значений для параметров, связанных с файлами.\n"
                            "3. Отключить функции включения файлов, если они не используются.\n"
                            "4. Регулярно обновлять и патчить ПО.\n"
                        ),
                        'code_examples': {
                            'python': (
                                "python\n"
                                "# Пример для Python с использованием белого списка разрешенных файлов\n\n"
                                "from flask import Flask, request, abort\n\n"
                                "app = Flask(__name__)\n\n"
                                "# Список разрешенных файлов\n"
                                "allowed_files = ['home.html', 'about.html', 'contact.html']\n\n"
                                "@app.route('/include')\n"
                                "def include_file():\n"
                                "    file = request.args.get('file')\n"
                                "    if file not in allowed_files:\n"
                                "        abort(400)\n"
                                "    return open(file).read()\n\n"
                                "if __name__ == '__main__':\n"
                                "    app.run()"
                            ),
                            'php': (
                                "php\n"
                                "<?php\n"
                                "// Пример для PHP с использованием белого списка разрешенных файлов\n\n"
                                "// Список разрешенных файлов\n"
                                "$allowed_files = ['home.php', 'about.php', 'contact.php'];\n\n"
                                "if (isset($_GET['file']) && in_array($_GET['file'], $allowed_files)) {\n"
                                "  include $_GET['file'];\n"
                                "} else {\n"
                                "  echo 'Недопустимый файл';\n"
                                "}\n"
                                "?>"
                            ),
                            'java': (
                                "java\n"
                                "import java.io.IOException;\n"
                                "import javax.servlet.ServletException;\n"
                                "import javax.servlet.annotation.WebServlet;\n"
                                "import javax.servlet.http.HttpServlet;\n"
                                "import javax.servlet.http.HttpServletRequest;\n"
                                "import javax.servlet.http.HttpServletResponse;\n"
                                "import java.util.Arrays;\n"
                                "import java.util.List;\n\n"
                                "@WebServlet(\"/include\")\n"
                                "public class IncludeServlet extends HttpServlet {\n"
                                "    private static final List<String> allowedFiles = Arrays.asList(\"home.jsp\", \"about.jsp\", \"contact.jsp\");\n\n"
                                "    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {\n"
                                "        String file = request.getParameter(\"file\");\n"
                                "        if (file == null || !allowedFiles.contains(file)) {\n"
                                "            response.sendError(HttpServletResponse.SC_BAD_REQUEST, \"Недопустимый файл\");\n"
                                "            return;\n"
                                "        }\n"
                                "        request.getRequestDispatcher(file).include(request, response);\n"
                                "    }\n"
                                "}"
                            ),
                            'javascript': (
                                "javascript\n"
                                "// Пример для Node.js с использованием белого списка разрешенных файлов\n\n"
                                "const express = require('express');\n"
                                "const fs = require('fs');\n"
                                "const path = require('path');\n\n"
                                "const app = express();\n\n"
                                "const allowedFiles = ['home.html', 'about.html', 'contact.html'];\n\n"
                                "app.get('/include', (req, res) => {\n"
                                "    const file = req.query.file;\n"
                                "    if (!allowedFiles.includes(file)) {\n"
                                "        return res.status(400).send('Недопустимый файл');\n"
                                "    }\n"
                                "    const filePath = path.join(__dirname, file);\n"
                                "    res.sendFile(filePath);\n"
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
    vulnerabilities = asyncio.run(analyze_lfi(scraped_data))
    with open('lfi_vulnerabilities.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
