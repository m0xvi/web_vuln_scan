import asyncio
import aiohttp
from pyppeteer import launch
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import logging
import json

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Указать конкретную версию Chromium для скачивания
chromium_executable_path = 'F:/code/Diplom/chrome-win/chrome.exe'

async def fetch_page(session, url, method='GET', data=None):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
        if method == 'GET':
            async with session.get(url, headers=headers, timeout=20) as response:
                return await response_data(response)
        elif method == 'POST':
            async with session.post(url, data=data, headers=headers, timeout=20) as response:
                return await response_data(response)
    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        return None

async def response_data(response):
    content = await response.text()
    return {
        'content': content,
        'status': response.status,
        'url': str(response.url),
        'headers': response.headers,
        'size': str(len(content) / 1024) + ' KB'
    }

async def process_js(url):
    browser = await launch(headless=True, executablePath=chromium_executable_path)
    page = await browser.newPage()
    await page.goto(url)
    content = await page.content()
    await browser.close()
    return content

async def get_links(html, base_url):
    links = set()
    soup = BeautifulSoup(html, 'html.parser')
    for link in soup.find_all('a', href=True):
        href = urljoin(base_url, link['href'])
        if urlparse(href).hostname == urlparse(base_url).hostname:
            links.add(href)
    return links

async def get_forms(soup, url):
    forms = []
    for form in soup.find_all('form'):
        form_details = {
            'action': urljoin(url, form.get('action', '')),
            'method': form.get('method', 'get').upper(),
            'inputs': []
        }
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            form_details['inputs'].append({
                'type': input_tag.get('type', 'text'),
                'name': input_tag.get('name'),
                'value': input_tag.get('value', '')
            })
        forms.append(form_details)
    logger.info(f"Extracted {len(forms)} forms from URL: {url}")
    return forms


async def submit_forms(session, forms, url):
    for form in forms:
        data = {input['name']: input['value'] for input in form['inputs'] if input['name']}
        if form['method'] == 'POST':
            await fetch_page(session, form['action'], 'POST', data)
        else:
            await fetch_page(session, form['action'], 'GET', data)

async def spider(base_url):
    results = []
    visited_urls = set()
    urls_to_visit = {base_url}

    async with aiohttp.ClientSession() as session:
        while urls_to_visit:
            url = urls_to_visit.pop()
            if url in visited_urls:
                continue
            visited_urls.add(url)

            logger.info(f"Visiting {url}")
            page_data = await fetch_page(session, url)
            if page_data and page_data['status'] == 200:
                content = await process_js(url) if 'html' in page_data['headers']['Content-Type'] else page_data['content']
                soup = BeautifulSoup(content, 'html.parser')
                forms = await get_forms(soup, url)

                results.append({
                    'URL': url,
                    'Method': 'GET',
                    'Parameters': parse_qs(urlparse(url).query),
                    'Page Title': soup.title.string if soup.title else 'No title',
                    'Page Size': page_data['size'],
                    'Status Code': page_data['status'],
                    'Forms': forms,
                    'HTML Content': content
                })

                new_links = await get_links(content, url)
                urls_to_visit.update(new_links - visited_urls)

        with open('scraped_data.json', 'w') as outfile:
            json.dump(results, outfile, indent=4)
        logger.info(f"Scraping finished for base URL: {base_url}")

    return results

if __name__ == '__main__':
    url = 'http://127.0.0.1:5000'
    asyncio.run(spider(url))
