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
    vulnerabilities = asyncio.run(analyze_rfi(scraped_data))
    with open('rfi_vulnerabilities.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
