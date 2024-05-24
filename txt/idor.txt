import aiohttp
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_idor(session, url, param, value):
    altered_value = str(int(value) + 1)
    altered_url = url.replace(f"{param}={value}", f"{param}={altered_value}")
    response = await session.get(altered_url)
    return altered_value in await response.text()

async def analyze_idor(scraped_data):
    vulnerabilities = []
    async with aiohttp.ClientSession() as session:
        for page in scraped_data:
            url = page['URL']
            params = page.get('Parameters', {})
            for param, value in params.items():
                if await test_idor(session, url, param, value):
                    vulnerabilities.append({
                        'url': url,
                        'parameter': param,
                        'is_vulnerable': True,
                        'type': 'IDOR',
                        'scan_data': f"Мы отправили запрос на {url} с измененным параметром {param} и получили доступ к чужим данным."
                    })
    return vulnerabilities
