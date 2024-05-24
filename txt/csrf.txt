import asyncio
import aiohttp
import logging
import json

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_csrf(session, url, form):
    # Попытка отправки формы без CSRF-токена
    form_data = {input['name']: input['value'] for input in form['inputs'] if input['name']}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    response = await session.post(url, data=form_data, headers=headers)
    return response.status != 403

async def analyze_csrf(scraped_data):
    vulnerabilities = []
    async with aiohttp.ClientSession() as session:
        for page in scraped_data:
            url = page['URL']
            forms = page.get('Forms', [])
            for form in forms:
                if await test_csrf(session, url, form):
                    vulnerabilities.append({
                        'url': url,
                        'parameter': 'N/A',
                        'is_vulnerable': True,
                        'type': 'CSRF',
                        'scan_data': f"Мы отправили форму на {url} без CSRF-токена и сервер принял запрос."
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
