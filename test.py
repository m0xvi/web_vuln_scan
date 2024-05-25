import asyncio
import json
from xss import analyze_xss, load_scraped_data

async def main():
    scraped_data = load_scraped_data('scraped_data.json')  # Загрузка данных скрапера
    vulnerabilities = await analyze_xss(scraped_data)  # Анализ уязвимостей
    print("XSS Scan Results:", json.dumps(vulnerabilities, indent=4))

if __name__ == '__main__':
    asyncio.run(main())
