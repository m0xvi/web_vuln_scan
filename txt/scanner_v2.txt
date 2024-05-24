from datetime import datetime
import aiohttp
import telebot
import multiprocessing
import asyncio
import logging
import time
import json
from scraper import spider
from sql import analyze_vulnerabilities as analyze_sql_vulnerabilities, load_scraped_data
from xss import analyze_xss
from csrf import analyze_csrf
from lfi import analyze_lfi
from rfi import analyze_rfi
from idor import analyze_idor
from recommendations import generate_recommendation
from requests.exceptions import ConnectionError, ReadTimeout
from tenacity import retry, stop_after_attempt, wait_fixed
from aiohttp import ClientSession, FormData
from urllib.parse import urlparse
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# Укажите токен вашего бота
TOKEN = '6979756435:AAG1dpmdnqwkBs6yXb1DJ9jpWhsCc8a16t0'
bot = telebot.TeleBot(TOKEN)

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Главное меню
main_menu_markup = telebot.types.ReplyKeyboardMarkup(resize_keyboard=True)
main_menu_markup.add('Начать сканирование', 'Помощь', 'О боте')

# Меню для выбора типа уязвимостей
scan_menu_markup = telebot.types.ReplyKeyboardMarkup(resize_keyboard=True)
scan_menu_markup.add('SQL Injection', 'XSS', 'CSRF', 'LFI', 'RFI', 'IDOR')
scan_menu_markup.add('Назад')

# Кнопка отмены
cancel_markup = telebot.types.ReplyKeyboardMarkup(resize_keyboard=True)
cancel_markup.add('Отмена')

# Глобальные переменные для хранения результатов и состояния сканирования
vulnerabilities = []
results = []
current_scan = None
pending_url = None

def format_results(vulnerabilities):
    formatted_results = []
    for vulnerability in vulnerabilities:
        if vulnerability.get('is_vulnerable'):
            scan_data = vulnerability.get('scan_data', 'N/A')
            risk_level = "Высокий" if vulnerability['is_vulnerable'] else "Низкий"
            formatted_result = (
                f"<b>Дата и время сканирования:</b> <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>\n"
                f"<b>URL:</b> <code>{vulnerability['url']}</code>\n"
                f"<b>Параметр:</b> <code>{vulnerability['parameter']}</code>\n"
                f"<b>Уязвимость:</b> {'<b>Да</b>' if vulnerability['is_vulnerable'] else 'Нет'}\n"
                f"<b>Тип уязвимости:</b> <code>{vulnerability['type']}</code>\n"
                f"<b>Payload:</b> <code>{vulnerability.get('payload', 'N/A')}</code>\n"
                f"<b>Время отклика:</b> <code>{vulnerability.get('response_time', 'N/A')}</code>\n"
                f"<b>Описание уязвимости:</b> {scan_data}\n"
                f"<b>Уровень риска:</b> {risk_level}\n"
            )
            formatted_results.append(formatted_result)
    logger.info(f"Total formatted results: {len(formatted_results)}")
    return formatted_results

def create_results_keyboard(page, total_pages):
    markup = InlineKeyboardMarkup()
    if page > 1:
        markup.add(InlineKeyboardButton(text='<--- Назад', callback_data=json.dumps({"method": "pagination", "page": page - 1})))
    markup.add(InlineKeyboardButton(text=f'{page}/{total_pages}', callback_data='noop'))
    if page < total_pages:
        markup.add(InlineKeyboardButton(text='Вперёд --->', callback_data=json.dumps({"method": "pagination", "page": page + 1})))
    markup.add(
        InlineKeyboardButton(text='Рекомендации', callback_data=json.dumps({"method": "recommend", "page": page})),
        InlineKeyboardButton(text='Отчет', callback_data='{"method": "report"}'),
        InlineKeyboardButton(text='Помощь', callback_data='{"method": "help"}')
    )
    return markup

def send_results_page(chat_id, page, message_id=None):
    logger.info(f"send_results_page called with page: {page}")
    load_results_from_file()  # Загружаем результаты из файла перед каждым отображением страницы
    logger.info(f"Current results: {results}")
    if not results:
        logger.error("No results to display.")
        bot.send_message(chat_id, "Нет результатов для отображения.")
        return

    total_pages = len(results)
    logger.info(f"Total pages: {total_pages}, Current results: {results}")
    if page < 1 or page > total_pages:
        logger.error(f"Requested page {page} is out of range, total results: {total_pages}")
        return
    results_message = results[page - 1]  # Страницы начинаются с 1
    markup = create_results_keyboard(page, total_pages)
    logger.info(f"Results message for page {page}: {results_message}")
    if message_id:
        bot.edit_message_text(results_message, chat_id, message_id, reply_markup=markup, parse_mode='HTML')
    else:
        bot.send_message(chat_id, results_message, reply_markup=markup, parse_mode='HTML')

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    try:
        logger.info(f"callback_query called with data: {call.data}")
        req = json.loads(call.data)
        if req['method'] == 'pagination':
            page = req['page']
            logger.info(f"Handling pagination to page: {page}")
            send_results_page(call.message.chat.id, page, call.message.message_id)
        elif req['method'] == 'noop':
            pass  # No operation, just a placeholder
        elif req['method'] == 'recommend':
            page = req['page']
            if page <= len(vulnerabilities):
                recommendation = generate_recommendation(vulnerabilities[page - 1]['type'])  # Индексы начинаются с 0
                bot.send_message(call.message.chat.id, recommendation)
            else:
                bot.send_message(call.message.chat.id, "Рекомендации недоступны для этой страницы.")
        elif req['method'] == 'report':
            send_report(call)
        elif req['method'] == 'help':
            send_help(call)
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in callback_query: {e}")
        bot.send_message(call.message.chat.id, f"Произошла ошибка декодирования JSON: {e}")
    except Exception as e:
        logger.error(f"Error in callback_query: {e}")
        bot.send_message(call.message.chat.id, f"Произошла ошибка: {e}")

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, """
    Привет! Я бот для сканирования уязвимостей на веб-страницах.

    Вот список доступных команд:

    /start - начать работу с ботом
    /help - отобразить это сообщение
    /cancel - отменить текущее сканирование

    /scan_sql <URL> - сканировать указанную страницу на наличие SQL-инъекций
    /scan_xss <URL> - сканировать указанную страницу на наличие Межсайтового скриптинга (XSS)
    /scan_csrf <URL> - сканировать указанную страницу на наличие Межсайтовой подделки запроса (CSRF)
    /scan_lfi <URL> - сканировать указанную страницу на наличие Локального включения файлов (LFI)
    /scan_rfi <URL> - сканировать указанную страницу на наличие Удаленного включения файлов (RFI)
    /scan_idor <URL> - сканировать указанную страницу на наличие Небезопасных прямых ссылок на объекты (IDOR)

    Пример использования:
    /scan_sql https://example.com/page
    """, reply_markup=main_menu_markup)

@bot.message_handler(commands=['cancel'])
def cancel_scan(message):
    global current_scan, pending_url
    if current_scan and current_scan.is_alive():
        current_scan.terminate()
        current_scan = None
        bot.reply_to(message, "Сканирование было отменено.", reply_markup=main_menu_markup)
    else:
        bot.reply_to(message, "Нет активного сканирования для отмены.", reply_markup=main_menu_markup)
    pending_url = None

@bot.message_handler(commands=['scan_sql', 'scan_xss', 'scan_csrf', 'scan_lfi', 'scan_rfi', 'scan_idor'])
def handle_scan_command(message):
    global pending_url
    command_parts = message.text.split()
    if len(command_parts) == 1:
        scan_type = command_parts[0].replace('/scan_', '').upper()
        bot.reply_to(message, f"Введите URL для сканирования на наличие {scan_type}. Например: http://example.com",
                     reply_markup=cancel_markup)
        pending_url = {'scan_type': scan_type, 'analyze_func': get_analyze_function(scan_type)}
        bot.register_next_step_handler(message, validate_url)
    else:
        url = command_parts[1]
        scan_type = command_parts[0].replace('/scan_', '').upper()
        handle_scan(message, get_analyze_function(scan_type), scan_type, url)

def get_analyze_function(scan_type):
    scan_type_to_function = {
        'SQL': analyze_sql_vulnerabilities,
        'XSS': analyze_xss,
        'CSRF': analyze_csrf,
        'LFI': analyze_lfi,
        'RFI': analyze_rfi,
        'IDOR': analyze_idor
    }
    return scan_type_to_function.get(scan_type, None)

@bot.message_handler(func=lambda message: message.text == 'Начать сканирование')
def start_scan(message):
    bot.reply_to(message, "Выберите тип уязвимости для сканирования:", reply_markup=scan_menu_markup)

@bot.message_handler(func=lambda message: message.text == 'Помощь')
def help(message):
    send_welcome(message)

@bot.message_handler(func=lambda message: message.text == 'О боте')
def about(message):
    about_text = (
        "Этот бот позволяет сканировать веб-приложения на наличие различных уязвимостей:\n"
        "- SQL Injection\n"
        "- XSS (Cross-Site Scripting)\n"
        "- CSRF (Cross-Site Request Forgery)\n"
        "- LFI (Local File Inclusion)\n"
        "- RFI (Remote File Inclusion)\n"
        "- IDOR (Insecure Direct Object Reference)\n\n"
        "Используемые технологии:\n"
        "- Python\n"
        "- Библиотеки: requests, aiohttp, telebot\n"
        "- Инструменты для анализа уязвимостей\n\n"
        "Важно: этот бот может выдавать ложные срабатывания и не является абсолютно достоверным инструментом по поиску и устранению уязвимостей веб-приложений."
    )
    bot.reply_to(message, about_text, reply_markup=main_menu_markup)

@bot.message_handler(func=lambda message: message.text == 'Назад')
def go_back(message):
    bot.reply_to(message, "Вы вернулись в главное меню. Выберите действие:", reply_markup=main_menu_markup)

@bot.message_handler(func=lambda message: message.text in ['SQL Injection', 'XSS', 'CSRF', 'LFI', 'RFI', 'IDOR'])
def handle_scan_type(message):
    global pending_url
    if current_scan and current_scan.is_alive():
        bot.reply_to(message, "Пожалуйста, подождите завершения текущего сканирования или отмените его командой /cancel.", reply_markup=main_menu_markup)
        return

    scan_type_to_function = {
        'SQL Injection': analyze_sql_vulnerabilities,
        'XSS': analyze_xss,
        'CSRF': analyze_csrf,
        'LFI': analyze_lfi,
        'RFI': analyze_rfi,
        'IDOR': analyze_idor
    }
    scan_type = message.text
    bot.reply_to(message, f"Введите URL для сканирования на наличие {scan_type}. Например: http://example.com",
                 reply_markup=cancel_markup)
    pending_url = {'scan_type': scan_type, 'analyze_func': scan_type_to_function[scan_type]}
    bot.register_next_step_handler(message, validate_url)

def validate_url(message):
    global pending_url
    url = message.text.strip()
    if url.lower() == 'отмена' or url.lower() == '/cancel':
        cancel_scan(message)
    elif url.startswith("http"):
        handle_scan(message, pending_url['analyze_func'], pending_url['scan_type'], url)
        pending_url = None
    else:
        bot.reply_to(message, "Пожалуйста, введите валидный URL, начиная с http:// или https://", reply_markup=cancel_markup)
        bot.register_next_step_handler(message, validate_url)

@bot.message_handler(func=lambda message: True)
def handle_text(message):
    if current_scan and current_scan.is_alive():
        if message.text.lower() in ['/cancel', 'отмена']:
            cancel_scan(message)
        else:
            bot.reply_to(message, "Пожалуйста, подождите завершения текущего сканирования или отмените его командой /cancel.")
    elif pending_url:
        validate_url(message)
    else:
        send_welcome(message)

def handle_scan(message, analyze_func, scan_type, url):
    global vulnerabilities, results, current_scan
    try:
        bot.reply_to(message, f"Начинаем сканирование сайта на наличие {scan_type}: {url}\n\nДля отмены сканирования введите /cancel, либо нажмите кнопку Отмена")
        queue = multiprocessing.Queue()
        current_scan = multiprocessing.Process(target=run_async_in_process,
                                               args=(queue, url, message.chat.id, analyze_func))
        current_scan.start()

        while current_scan.is_alive():
            bot.send_chat_action(message.chat.id, 'typing')
            time.sleep(5)

        current_scan.join()
        vulnerabilities = queue.get()
        logger.info(f"Vulnerabilities after scan: {vulnerabilities}")

        if 'error' in vulnerabilities:
            bot.reply_to(message, f"Произошла ошибка: {vulnerabilities['error']}")
        else:
            results = format_results(vulnerabilities)
            save_results_to_file(results)
            logger.info(f"Total results: {len(results)}")
            send_results_page(message.chat.id, 1)
    except Exception as e:
        logger.error(f"Error in handle_scan: {e}")
        bot.reply_to(message, f"Произошла ошибка: {e}")

def save_results_to_file(results):
    try:
        with open('results.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=4)
        logger.info("Results saved to results.json")
    except Exception as e:
        logger.error(f"Error saving results to file: {e}")

def load_results_from_file():
    global results
    try:
        with open('results.json', 'r', encoding='utf-8') as f:
            results = json.load(f)
        logger.info("Results loaded from results.json")
    except Exception as e:
        logger.error(f"Error loading results from file: {e}")

def run_async_in_process(queue, url, chat_id, analyze_func):
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(spider_and_analyze(url, chat_id, analyze_func))
        queue.put(results)
    except Exception as e:
        logger.error(f"Error in run_async_in_process: {e}")
        queue.put({'error': str(e)})
    finally:
        loop.close()

async def spider_and_analyze(url, chat_id, analyze_func):
    try:
        await send_message_with_retry(chat_id, "Сканирование началось, пожалуйста, подождите...")

        logger.info(f"Starting spider for URL: {url}")
        await spider(url)  # Запуск скрапера
        logger.info(f"Spider finished for URL: {url}")

        await send_message_with_retry(chat_id, "Сканирование завершено, анализ данных...")

        scraped_data = load_scraped_data('scraped_data.json')  # Загрузка данных скрапера
        logger.info(f"Scraped data loaded: {scraped_data}")

        vulnerabilities = await analyze_func(scraped_data)  # Анализ уязвимостей
        logger.info(f"Vulnerabilities found: {vulnerabilities}")

        # Формирование сообщения и файла с результатами
        results.clear()
        formatted_results = format_results(vulnerabilities)
        results.extend(formatted_results)
        save_results_to_file(results)
        logger.info(f"Total results: {len(results)}")
        generate_detailed_report(scraped_data, vulnerabilities)

        # Отправка сообщения с результатами
        send_results_page(chat_id, 1)

        return vulnerabilities
    except Exception as e:
        logger.error(f"Error in spider_and_analyze: {e}")
        await send_message_with_retry(chat_id, f"Произошла ошибка при анализе: {e}")
        return {'error': str(e)}

async def send_message_with_retry(chat_id, message, timeout=60):
    try:
        async with ClientSession() as session:
            url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
            payload = {
                'chat_id': str(chat_id),
                'text': message,
                'parse_mode': 'HTML'
            }
            async with session.post(url, data=payload, timeout=timeout) as response:
                if response.status != 200:
                    logger.error(f"Failed to send message: {await response.text()}")
                else:
                    logger.info(f"Message sent successfully: {message}")
    except (ConnectionError, ReadTimeout) as e:
        logger.error(f"Error sending message: {e}")
        raise

@bot.callback_query_handler(func=lambda call: call.data == '{"method": "report"}')
def send_report(call):
    try:
        bot.send_document(call.message.chat.id, open('report.txt', 'rb'))
    except Exception as e:
        logger.error(f"Error in send_report: {e}")

@bot.callback_query_handler(func=lambda call: call.data == '{"method": "help"}')
def send_help(call):
    send_welcome(call.message)

def generate_detailed_report(scraped_data, vulnerabilities):
    report = "Детальный отчет сканирования:\n\n"
    report += "=== Данные скрапера ===\n"
    for page in scraped_data:
        report += f"URL: {page['URL']}\n"
        report += f"Метод: {page['Method']}\n"
        report += f"Параметры: {json.dumps(page['Parameters'], indent=4)}\n"
        report += f"Заголовок страницы: {page['Page Title']}\n"
        report += f"Размер страницы: {page['Page Size']}\n"
        report += f"Код состояния: {page['Status Code']}\n"
        report += "Формы:\n"
        for form in page.get('Forms', []):
            report += f"  Action: {form['action']}\n"
            report += f"  Method: {form['method']}\n"
            report += "  Inputs:\n"
            for input_tag in form['inputs']:
                report += f"    - {input_tag}\n"
        report += "-----------------------------------\n"

    report += "\n=== Найденные уязвимости ===\n"
    for result in vulnerabilities:
        report += f"URL: {result['url']}\n"
        report += f"Параметр: {result['parameter']}\n"
        report += f"Уязвимость: {'Да' if result['is_vulnerable'] else 'Нет'}\n"
        report += f"Тип уязвимости: {result['type']}\n"
        if 'payload' in result:
            report += f"Payload: {result['payload']}\n"
        if 'response_time' in result:
            report += f"Время отклика: {result['response_time']}\n"
        report += f"Рекомендация: {generate_recommendation(result['type'])}\n"
        report += "-----------------------------------\n"

    report_path = "report.txt"
    with open(report_path, 'w', encoding='utf-8') as file:
        file.write(report)
    logger.info(f"Detailed report generated at {report_path}")
    return report_path

if __name__ == "__main__":
    try:
        bot.polling(none_stop=True)
    except Exception as e:
        logger.error(f"Error during polling: {e}")