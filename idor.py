import asyncio
import aiohttp
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_idor(session, url, param, value):
    if isinstance(value, list):
        value = value[0]
    try:
        original_value = int(value)
        altered_value = str(original_value + 1)
    except ValueError:
        logger.error(f"Cannot convert value to int: {value}")
        return False, None
    altered_url = url.replace(f"{param}={value}", f"{param}={altered_value}")
    logger.info(f"Testing IDOR with URL: {altered_url}")
    try:
        response = await session.get(altered_url)
        response_text = await response.text()
        logger.info(f"Response for {altered_url}: {response_text[:100]}")  # Логируем первые 100 символов ответа

        # Проверяем, что ответ содержит данные другого пользователя
        if response.status == 200 and altered_value in altered_url and "User not found" not in response_text:
            logger.info(f"IDOR vulnerability found: {altered_url}")
            return True, altered_url
    except Exception as e:
        logger.error(f"Error testing IDOR payload on {url}: {e}")
    return False, None

async def analyze_idor(scraped_data):
    vulnerabilities = []
    async with aiohttp.ClientSession() as session:
        for page in scraped_data:
            url = page['URL']
            params = page.get('Parameters', {})
            for param, value in params.items():
                logger.info(f"Analyzing URL: {url} with param: {param}")
                is_vulnerable, vulnerable_url = await test_idor(session, url, param, value)
                if is_vulnerable:
                    vulnerabilities.append({
                        'url': url,
                        'parameter': param,
                        'is_vulnerable': True,
                        'type': 'IDOR',
                        'payload': vulnerable_url,
                        'description': (
                            "IDOR (Insecure Direct Object Reference) уязвимость позволяет злоумышленнику получать доступ к данным других пользователей, "
                            "изменяя значения параметров в URL."
                        ),
                        'risk_level': "🟠 Средний",
                        'recommendation': (
                            "Для предотвращения IDOR атак рекомендуется:\n"
                            "1. Использовать проверки прав доступа на сервере для каждого запроса.\n"
                            "2. Не полагаться только на скрытие параметров в URL для обеспечения безопасности.\n"
                            "3. Использовать сложные идентификаторы объектов, которые трудно предугадать.\n"
                            "4. Регулярно проверять и обновлять код для предотвращения уязвимостей."
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
    vulnerabilities = asyncio.run(analyze_idor(scraped_data))
    with open('idor_vulnerabilities.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
