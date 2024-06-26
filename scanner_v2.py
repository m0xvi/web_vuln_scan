import html
from datetime import datetime
import aiohttp
import telebot
import multiprocessing
import asyncio
import logging
import time
import json
from telebot import types
from scraper import spider
from sql import analyze_vulnerabilities as analyze_sql_vulnerabilities, load_scraped_data
from xss import analyze_xss
from csrf import analyze_csrf
from lfi import analyze_lfi
from rfi import analyze_rfi
from idor import analyze_idor
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
main_menu_markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
main_menu_markup.row(types.KeyboardButton('🔍 Начать сканирование'))
main_menu_markup.row(types.KeyboardButton('ℹ️ Помощь'), types.KeyboardButton('🤖 О боте'))

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


def escape_html(text):
    return html.escape(text)


def format_results(vulnerabilities):
    formatted_results = []
    for vulnerability in vulnerabilities:
        if vulnerability.get('is_vulnerable'):
            result_parts = []

            # Обязательные поля
            result_parts.append(
                f"<b>📆 Дата и время сканирования:</b> <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>")
            result_parts.append(f"<b>📄 URL:</b> <code>{escape_html(str(vulnerability['url']))}</code>")
            result_parts.append(f"<b>⚠️ Уязвимость:</b> {'<b>Да</b>' if vulnerability['is_vulnerable'] else 'Нет'}")
            result_parts.append(
                f"<b>☠️ Тип уязвимости:</b> <code>{escape_html(str(vulnerability.get('type', 'Unknown')))}</code>")

            # Опциональные поля
            if 'parameter' in vulnerability:
                result_parts.append(f"<b>📌 Параметр:</b> <code>{escape_html(str(vulnerability['parameter']))}</code>")
            if 'payload' in vulnerability:
                result_parts.append(f"<b>⚙️ Payload:</b> <code>{escape_html(str(vulnerability['payload']))}</code>")
            if 'response_time' in vulnerability:
                result_parts.append(
                    f"<b>⏳ Время отклика:</b> <code>{escape_html(str(vulnerability['response_time']))}</code>")
            if 'form_action' in vulnerability:
                result_parts.append(
                    f"<b>🔗 Action формы:</b> <code>{escape_html(str(vulnerability['form_action']))}</code>")
            if 'form_method' in vulnerability:
                result_parts.append(
                    f"<b>📝 Метод формы:</b> <code>{escape_html(str(vulnerability['form_method']))}</code>")
            if 'form_fields' in vulnerability:
                result_parts.append(
                    f"<b>🔍 Поля формы:</b> <code>{escape_html(', '.join(vulnerability['form_fields']))}</code>")

            result_parts.append(f"<b>🔍 Уровень риска:</b> {escape_html(str(vulnerability.get('risk_level', '🔵 Нет')))}")
            result_parts.append(
                f"<b>📄 Описание уязвимости:</b> {escape_html(vulnerability.get('description', 'Описание уязвимости не найдено.'))}")

            formatted_result = '\n'.join(result_parts)
            formatted_results.append(formatted_result)

    logger.info(f"Total formatted results: {len(formatted_results)}")
    return formatted_results


def create_results_keyboard(page, total_pages):
    markup = InlineKeyboardMarkup(row_width=3)
    buttons = []
    if page > 1:
        buttons.append(
            InlineKeyboardButton(text='◀️ Назад', callback_data=json.dumps({"method": "pagination", "page": page - 1})))
    buttons.append(InlineKeyboardButton(text=f'{page}/{total_pages}', callback_data='noop'))
    if page < total_pages:
        buttons.append(InlineKeyboardButton(text='Вперед ▶️',
                                            callback_data=json.dumps({"method": "pagination", "page": page + 1})))
    markup.row(*buttons)
    markup.add(
        InlineKeyboardButton(text='Рекомендации', callback_data=json.dumps({"method": "recommend", "page": page})),
        InlineKeyboardButton(text='Отчет', callback_data='{"method": "report"}'),
        InlineKeyboardButton(text='ℹ️ Помощь', callback_data='{"method": "help"}')
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
            logger.info(f"Handling recommendations for page: {page}")
            vulnerability = vulnerabilities[page - 1]
            recommendation = vulnerability.get('recommendation', 'Рекомендации не найдены.')
            code_example = vulnerability['code_examples'].get('python', 'Пример кода не найден.')
            recommendation_message = bot.send_message(call.message.chat.id, recommendation)
            send_code_example(call.message.chat.id, recommendation_message.message_id, code_example, vulnerability, 'python', page)
        elif req['method'] == 'change_code_example':
            page = req['page']
            language = req['lang']  # Используем ключ 'lang'
            vulnerability = vulnerabilities[page - 1]
            code_example = vulnerability['code_examples'].get(language, 'Пример кода не найден.')
            update_code_example(call.message.chat.id, call.message.message_id, code_example, vulnerability, language, page)
        elif req['method'] == 'report':
            send_report(call)
        elif req['method'] == 'help':
            send_help(call.message)  # Передаем call.message, а не сам call
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in callback_query: {e}")
        bot.send_message(call.message.chat.id, f"Произошла ошибка декодирования JSON: {e}")
    except Exception as e:
        logger.error(f"Error in callback_query: {e}")
        bot.send_message(call.message.chat.id, f"Произошла ошибка: {e}")



def send_code_example(chat_id, message_id, code_example, vulnerability, language, page):
    markup = InlineKeyboardMarkup()
    buttons = [
        InlineKeyboardButton(text='Python', callback_data=json.dumps({"method": "change_code_example", "lang": "python", "page": page})),
        InlineKeyboardButton(text='PHP', callback_data=json.dumps({"method": "change_code_example", "lang": "php", "page": page})),
        InlineKeyboardButton(text='Java', callback_data=json.dumps({"method": "change_code_example", "lang": "java", "page": page}))
    ]
    markup.add(*buttons)
    bot.send_message(chat_id, f"```{code_example}```", parse_mode='Markdown', reply_markup=markup)

def update_code_example(chat_id, message_id, code_example, vulnerability, language, page):
    markup = InlineKeyboardMarkup()
    buttons = [
        InlineKeyboardButton(text='Python', callback_data=json.dumps({"method": "change_code_example", "lang": "python", "page": page})),
        InlineKeyboardButton(text='PHP', callback_data=json.dumps({"method": "change_code_example", "lang": "php", "page": page})),
        InlineKeyboardButton(text='Java', callback_data=json.dumps({"method": "change_code_example", "lang": "java", "page": page}))
    ]
    markup.add(*buttons)
    try:
        bot.edit_message_text(f"```{code_example}```", chat_id, message_id, parse_mode='Markdown', reply_markup=markup)
    except Exception as e:
        logger.error(f"Error updating code example: {e}")
        bot.send_message(chat_id, f"Произошла ошибка при обновлении примера кода: {e}")




@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, """
    👋 Привет! Я бот для сканирования уязвимостей на веб-страницах.

    Вот список доступных команд:

    /start - начать работу с ботом
    /help - отобразить это сообщение
    /cancel - отменить текущее сканирование

    💉 /scan_sql <URL> - сканировать указанную страницу на наличие SQL-инъекций
    ✂️ /scan_xss <URL> - сканировать указанную страницу на наличие Межсайтового скриптинга (XSS)
    🍪 /scan_csrf <URL> - сканировать указанную страницу на наличие Межсайтовой подделки запроса (CSRF)
    📥 /scan_lfi <URL> - сканировать указанную страницу на наличие Локального включения файлов (LFI)
    📤 /scan_rfi <URL> - сканировать указанную страницу на наличие Удаленного включения файлов (RFI)
    🔗 /scan_idor <URL> - сканировать указанную страницу на наличие Небезопасных прямых ссылок на объекты (IDOR)

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


@bot.message_handler(func=lambda message: message.text == '🔍 Начать сканирование')
def start_scan(message):
    bot.reply_to(message, "Выберите тип уязвимости для сканирования:", reply_markup=scan_menu_markup)


@bot.callback_query_handler(func=lambda call: call.data == '{"method": "help"}')
def send_help(message):
    send_welcome(message)  # Вызываем send_welcome с message


@bot.message_handler(func=lambda message: message.text == '🤖 О боте')
def about(message):
    about_text = (
        "Этот бот позволяет сканировать веб-приложения на наличие различных уязвимостей:\n"
        "- SQL Injection (SQL-инъекции): SQL-инъекция позволяет злоумышленнику вмешиваться в запросы, которые приложение отправляет в базу данных. Это может привести к несанкционированному доступу к данным, их модификации или удалению.\n"
        "- XSS (Cross-Site Scripting, межсайтовый скриптинг): XSS позволяет внедрять вредоносные скрипты на веб-страницы, которые затем выполняются в браузерах пользователей. Это может привести к краже данных сессий, подмене контента и распространению вредоносного ПО.\n"
        "- CSRF (Cross-Site Request Forgery, межсайтовая подделка запроса): CSRF позволяет злоумышленнику заставить пользователя выполнить нежелательные действия на сайте, на котором он авторизован. Это может привести к изменению настроек пользователя, выполнению транзакций и другим нежелательным действиям.\n"
        "- LFI (Local File Inclusion, локальное включение файлов): LFI позволяет злоумышленнику получить доступ к локальным файлам на сервере, используя относительные пути в параметрах URL. Это может привести к утечке конфиденциальной информации, такой как конфигурационные файлы и исходный код.\n"
        "- RFI (Remote File Inclusion, удаленное включение файлов): RFI позволяет злоумышленнику включать удаленные файлы на сервере, используя параметры URL. Это может привести к выполнению произвольного кода и полной компрометации сервера.\n"
        "- IDOR (Insecure Direct Object Reference, небезопасное прямое обращение к объекту): IDOR позволяет злоумышленнику получать доступ к данным других пользователей, изменяя значения параметров в URL. Это может привести к утечке конфиденциальной информации и несанкционированным изменениям данных.\n\n"
        "Функциональность бота включает:\n"
        "- Автоматическое сканирование веб-приложений на указанные типы уязвимостей\n"
        "- Формирование подробных отчетов по результатам сканирования\n"
        "- Интерактивное взаимодействие через команды и кнопки\n\n"
        "Используемые технологии:\n"
        "- Язык программирования: Python\n"
        "- Библиотеки: requests, aiohttp, telebot, multiprocessing, asyncio\n"
        "- Инструменты для анализа уязвимостей и скрапинга веб-страниц\n\n"
        "Особенности:\n"
        "- Поддержка асинхронных операций для эффективного выполнения сканирований\n"
        "- Возможность работы с несколькими типами уязвимостей\n"
        "- Поддержка команд для управления сканированиями и получения помощи\n\n"
        "Примеры использования:\n"
        "- /scan_sql <URL> - сканировать указанную страницу на наличие SQL-инъекций\n"
        "- /scan_xss <URL> - сканировать указанную страницу на наличие XSS\n"
        "- /scan_csrf <URL> - сканировать указанную страницу на наличие CSRF\n"
        "- /scan_lfi <URL> - сканировать указанную страницу на наличие LFI\n"
        "- /scan_rfi <URL> - сканировать указанную страницу на наличие RFI\n"
        "- /scan_idor <URL> - сканировать указанную страницу на наличие IDOR\n\n"
        "Важно: этот бот может выдавать ложные срабатывания и не является абсолютно достоверным инструментом по поиску и устранению уязвимостей веб-приложений. "
        "Рекомендуется использовать результаты сканирования в качестве предварительного анализа и дополнительно проверять найденные уязвимости вручную."
    )
    bot.reply_to(message, about_text, reply_markup=main_menu_markup)


@bot.message_handler(func=lambda message: message.text == 'Назад')
def go_back(message):
    bot.reply_to(message, "Вы вернулись в главное меню. Выберите действие:", reply_markup=main_menu_markup)


@bot.message_handler(func=lambda message: message.text in ['SQL Injection', 'XSS', 'CSRF', 'LFI', 'RFI', 'IDOR'])
def handle_scan_type(message):
    global pending_url
    if current_scan and current_scan.is_alive():
        bot.reply_to(message,
                     "Пожалуйста, подождите завершения текущего сканирования или отмените его командой /cancel.",
                     reply_markup=main_menu_markup)
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
        bot.reply_to(message, "Пожалуйста, введите валидный URL, начиная с http:// или https://",
                     reply_markup=cancel_markup)
        bot.register_next_step_handler(message, validate_url)


@bot.message_handler(func=lambda message: True)
def handle_text(message):
    if current_scan and current_scan.is_alive():
        if message.text.lower() in ['/cancel', 'отмена']:
            cancel_scan(message)
        else:
            bot.reply_to(message,
                         "Пожалуйста, подождите завершения текущего сканирования или отмените его командой /cancel.")
    elif pending_url:
        validate_url(message)
    else:
        send_welcome(message)


def handle_scan(message, analyze_func, scan_type, url):
    global vulnerabilities, results, current_scan
    try:
        bot.reply_to(message,
                     f"🔍 Начинаем сканирование сайта на наличие {scan_type}: {url}\n\nДля отмены сканирования введите /cancel, либо нажмите кнопку Отмена")
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
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(spider_and_analyze(url, chat_id, analyze_func))
    queue.put(results)


async def spider_and_analyze(url, chat_id, analyze_func):
    try:
        start_time = datetime.now()  # Время начала сканирования
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
        end_time = datetime.now()  # Время окончания сканирования
        report_path = generate_detailed_report(scraped_data, vulnerabilities, start_time, end_time)

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
    send_welcome(call)


def generate_detailed_report(scraped_data, vulnerabilities, start_time, end_time):
    report = "Детальный отчет сканирования:\n\n"
    report += "=== Основные данные ===\n"
    report += f"URL сканируемого веб-приложения: {scraped_data[0]['URL']}\n"
    report += f"Дата и время начала сканирования: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += f"Время, затраченное на сканирование: {str(end_time - start_time)}\n"
    report += f"Метод сканирования: Полный скан\n\n"

    report += "=== Общая информация об уязвимостях ===\n"
    report += f"Общее количество найденных уязвимостей: {len(vulnerabilities)}\n"
    for idx, result in enumerate(vulnerabilities, 1):
        report += f"{idx}. Тип: {result['type']}, Риск-уровень: {result['risk_level']}\n"
        report += f"Описание: {result['description']}\n\n"

    report += "=== Детали каждой уязвимости ===\n"
    for idx, result in enumerate(vulnerabilities, 1):
        report += f"Уязвимость {idx}:\n"
        report += f"URL: {result.get('url', 'Неизвестно')}\n"
        report += f"Параметр: {result.get('parameter', 'Неизвестно')}\n"
        report += f"Тип уязвимости: {result['type']}\n"
        report += f"Риск-уровень: {result['risk_level']}\n"
        report += f"Описание уязвимости: {result['description']}\n"
        report += f"Рекомендации:\n{result.get('recommendation', 'Рекомендации не найдены.')}\n"
        if 'code_examples' in result:
            report += "Примеры кода:\n"
            for lang, code in result['code_examples'].items():
                report += f"{lang.capitalize()}:\n{code}\n"
        report += "-----------------------------------\n"

    report += "\n=== Данные о сканируемых страницах ===\n"
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

    report += "\n=== Статистика сканирования ===\n"
    report += f"Время, затраченное на сканирование: {str(end_time - start_time)}\n"
    report += f"Количество сканированных страниц: {len(scraped_data)}\n"
    report += f"Количество проверенных форм: {sum(len(page.get('Forms', [])) for page in scraped_data)}\n"
    report += f"Количество проверенных параметров: {sum(len(page.get('Parameters', {})) for page in scraped_data)}\n"

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
