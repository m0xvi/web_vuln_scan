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
                        )
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
