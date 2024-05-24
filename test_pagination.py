import telebot
import json
import logging
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# Укажите токен вашего бота
TOKEN = '6979756435:AAG1dpmdnqwkBs6yXb1DJ9jpWhsCc8a16t0'
bot = telebot.TeleBot(TOKEN)

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Глобальная переменная для хранения результатов
results = []

# Функция для форматирования тестовых данных
def format_test_results():
    formatted_results = []
    for i in range(1, 11):  # Создаем 10 тестовых записей
        formatted_result = (
            f"<b>Дата и время сканирования:</b> <code>2024-05-24 02:12:10</code>\n"
            f"<b>URL:</b> <code>http://example.com/test_page_{i}</code>\n"
            f"<b>Параметр:</b> <code>test_parameter_{i}</code>\n"
            f"<b>Уязвимость:</b> <b>Да</b>\n"
            f"<b>Тип уязвимости:</b> <code>Test Type {i}</code>\n"
            f"<b>Payload:</b> <code>test_payload_{i}</code>\n"
            f"<b>Время отклика:</b> <code>N/A</code>\n"
            f"<b>Описание уязвимости:</b> Тестовое описание уязвимости {i}\n"
            f"<b>Уровень риска:</b> Высокий\n"
        )
        formatted_results.append(formatted_result)
    logger.info(f"Total formatted test results: {len(formatted_results)}")
    return formatted_results

# Заполняем результаты тестовыми данными
results = format_test_results()

def create_results_keyboard(page, total_pages):
    markup = InlineKeyboardMarkup()
    if page > 1:
        markup.add(InlineKeyboardButton(text='<--- Назад', callback_data=json.dumps({"method": "pagination", "page": page - 1})))
    markup.add(InlineKeyboardButton(text=f'{page}/{total_pages}', callback_data='noop'))
    if page < total_pages:
        markup.add(InlineKeyboardButton(text='Вперёд --->', callback_data=json.dumps({"method": "pagination", "page": page + 1})))
    return markup

def send_results_page(chat_id, page, message_id=None):
    logger.info(f"send_results_page called with page: {page}")
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
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in callback_query: {e}")
        bot.send_message(call.message.chat.id, f"Произошла ошибка декодирования JSON: {e}")
    except Exception as e:
        logger.error(f"Error in callback_query: {e}")
        bot.send_message(call.message.chat.id, f"Произошла ошибка: {e}")

@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "Привет! Используйте команду /test_pagination для начала теста.", reply_markup=telebot.types.ReplyKeyboardRemove())

@bot.message_handler(commands=['test_pagination'])
def start_test_pagination(message):
    logger.info("Starting test pagination")
    send_results_page(message.chat.id, 1)

if __name__ == "__main__":
    try:
        bot.polling(none_stop=True)
    except Exception as e:
        logger.error(f"Error during polling: {e}")
