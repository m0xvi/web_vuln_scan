import logging
import json
import re
import itertools
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_fixed
from aiohttp.client_exceptions import ClientError

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Static Analysis Functions
def find_vulnerable_scripts(html):
    soup = BeautifulSoup(html, 'html.parser')
    scripts = soup.find_all('script')
    vulnerabilities = []

    for script in scripts:
        script_content = script.string
        if script_content:
            if re.search(r'document\.write', script_content) or re.search(r'innerHTML', script_content):
                vulnerabilities.append({
                    'url': 'N/A',
                    'parameter': 'N/A',
                    'payload': script_content.strip(),
                    'method': 'N/A',
                    'vulnerable': True,
                    'is_vulnerable': True,
                    'type': 'Static Analysis',
                    'description': "Найдена потенциально уязвимая JavaScript функция, которая использует 'document.write' или 'innerHTML'. "
                                   "Эти функции могут быть использованы для внедрения вредоносного кода, если данные не проходят соответствующую валидацию и экранирование.",
                    'risk_level': '🔴 Высокий',
                    'recommendation': (
                        "Рекомендуется избегать использования 'document.write' и 'innerHTML'. "
                        "Вместо этого используйте безопасные методы манипуляции DOM, такие как 'textContent' или 'innerText'. "
                        "Также убедитесь, что все данные, используемые в этих функциях, проходят валидацию и экранирование."
                    )
                })
    return vulnerabilities

# Dynamic Analysis Functions
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
async def send_request(session, url, method, data=None, headers=None, cookies=None):
    try:
        logger.info(f"Sending {method} request to {url} with data: {data} and headers: {headers}")
        if method == 'GET':
            async with session.get(url, headers=headers, cookies=cookies) as response:
                return await response.text()
        elif method == 'POST':
            async with session.post(url, data=data, headers=headers, cookies=cookies) as response:
                return await response.text()
    except ClientError as e:
        logger.error(f"Request error: {e}")
        raise

async def test_xss_injection(session, url, param, payload, method, headers=None, cookies=None):
    if method == 'GET':
        full_url = f"{url}?{param}={payload}"
        response_text = await send_request(session, full_url, method, headers=headers, cookies=cookies)
    elif method == 'POST':
        data = {param: payload}
        response_text = await send_request(session, url, method, data=data, headers=headers, cookies=cookies)

    if response_text and payload in response_text:
        logger.info(f"XSS vulnerability found with payload: {payload} in {url}")
        return {
            'url': url,
            'parameter': param,
            'payload': payload,
            'method': method,
            'vulnerable': True,
            'is_vulnerable': True,
            'type': 'XSS',
            'description': "Обнаружена уязвимость межсайтового скриптинга (XSS). "
                           "XSS позволяет злоумышленнику внедрить вредоносный скрипт, который выполнится в браузере пользователя, "
                           "что может привести к краже данных, подделке запросов или выполнению произвольного кода.",
            'risk_level': '🔴 Высокий',
            'recommendation': (
                "Для предотвращения XSS атак рекомендуется:\n"
                "1. Экранировать все входные данные перед их выводом на страницу.\n"
                "   Пример для Python:\n"
                "   ```python\n"
                "   from markupsafe import escape\n"
                "   safe_input = escape(user_input)\n"
                "   ```\n"
                "2. Использовать Content Security Policy (CSP) для ограничения источников выполнения скриптов.\n"
                "   Пример настройки CSP:\n"
                "   ```html\n"
                "   <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self';\">\n"
                "   ```\n"
                "3. Проверять и фильтровать все входные данные, используя белые списки допустимых значений.\n"
                "4. Использовать безопасные функции для манипуляции DOM, такие как 'textContent' вместо 'innerHTML'."
            )
        }
    return {
        'url': url,
        'parameter': param,
        'payload': payload,
        'method': method,
        'vulnerable': False,
        'is_vulnerable': False,
        'type': 'XSS',
        'description': "Уязвимость межсайтового скриптинга (XSS) не обнаружена.",
        'risk_level': '🟢 Низкий',
        'recommendation': "Убедитесь, что все входные данные всегда проходят валидацию и экранирование."
    }

def generate_heuristic_payloads():
    base_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg/onload=alert('XSS')>"]
    attributes = ["src", "href", "onload", "onerror", "onclick"]
    events = ["onload", "onerror", "onclick", "onmouseover", "onfocus"]

    heuristic_payloads = base_payloads.copy()
    for attribute, event in itertools.product(attributes, events):
        heuristic_payloads.append(f"<img {attribute}=x {event}=alert('XSS')>")
        heuristic_payloads.append(f"<a {attribute}=x {event}=alert('XSS')>Click me</a>")
    return heuristic_payloads

async def analyze_xss(scraped_data):
    vulnerabilities = []
    logger.info(f"Analyzing XSS vulnerabilities for scraped data: {json.dumps(scraped_data, indent=4)}")
    xss_payloads = {
        "basic": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
        "advanced": [
            "<svg/onload=alert('XSS')>",
            "<details/open ontoggle=alert('XSS')>",
            "<a href='javascript:alert(\"XSS\")'>Click me</a>"
        ],
        "dom_based": ["<script>document.body.innerHTML='XSS'</script>"],
        "heuristic": generate_heuristic_payloads()[:5]
    }

    async with aiohttp.ClientSession() as session:
        tasks = []

        for page in scraped_data:
            url = page.get('URL', '')
            if not url:
                logger.error(f"Skipping entry due to missing 'URL' key: {page}")
                continue

            forms = page.get('Forms', [])
            html_content = page.get('HTML Content', '')

            logger.info(f"Processing URL: {url}")
            logger.info(f"Forms: {json.dumps(forms, indent=4)}")
            logger.info(f"HTML Content: {html_content[:200]}...")

            static_vulnerabilities = find_vulnerable_scripts(html_content)
            if static_vulnerabilities:
                vulnerabilities.extend(static_vulnerabilities)

            for form in forms:
                action = form['action'] if form['action'] else url
                method = form['method']
                inputs = form['inputs']
                for input_field in inputs:
                    name = input_field['name']
                    if not name:
                        continue

                    for payload_type, payload_list in xss_payloads.items():
                        for payload in payload_list:
                            tasks.append(
                                test_xss_injection(session, action, name, payload, method)
                            )

            url_params = page.get('Parameters', {})
            for param, value in url_params.items():
                for payload_type, payload_list in xss_payloads.items():
                    for payload in payload_list:
                        tasks.append(
                            test_xss_injection(session, url, param, payload, 'GET')
                        )

            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
            for header in ['User-Agent', 'Referer']:
                for payload_type, payload_list in xss_payloads.items():
                    for payload in payload_list:
                        new_headers = headers.copy()
                        new_headers[header] = payload
                        tasks.append(
                            test_xss_injection(session, url, header, payload, 'GET', new_headers)
                        )

        results = await asyncio.gather(*tasks)
        for result in results:
            if result.get('vulnerable'):
                vulnerabilities.append(result)

    logger.info(f"XSS vulnerabilities found: {json.dumps(vulnerabilities, indent=4)}")
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
    vulnerabilities = asyncio.run(analyze_xss(scraped_data))
    print("XSS Scan Results:", json.dumps(vulnerabilities, indent=4))
