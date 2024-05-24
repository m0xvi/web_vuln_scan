import telebot
from telebot import types
import modules.sqld as sqld
import re
import logging
import requests
import os
import time


bot = telebot.TeleBot("6979756435:AAG1dpmdnqwkBs6yXb1DJ9jpWhsCc8a16t0")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_authentication_required(url):
    try:
        response = requests.get(url)
        if response.status_code == 401:  # Код 401 указывает на необходимость аутентификации
            return True
        else:
            return False
    except Exception as e:
        logger.error(f"Ошибка при проверке аутентификации: {e}")
        return False

@bot.message_handler(commands=['start', 'help'])
def handle_help(message):
    # Определение текста помощи
    help_text = """
    Привет! Я бот для сканирования уязвимостей на веб-страницах.

    Вот список доступных команд:
    /start - начать работу с ботом
    /help - отобразить это сообщение
    /scan_sql <URL> - сканировать указанную страницу на наличие SQL-инъекций

    Пример использования:
    /scan_sql https://example.com/page
    """
    # Отправка сообщения с помощью
    bot.send_message(message.chat.id, help_text)

    # Создание клавиатуры с выбором действия
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    item1 = types.KeyboardButton("Выбрать уязвимость для сканирования")
    item2 = types.KeyboardButton("Помощь")
    item3 = types.KeyboardButton("Рекомендации")
    markup.add(item1, item2, item3)
    bot.send_message(message.chat.id, "Выберите действие:", reply_markup=markup)

@bot.message_handler(content_types=['text'])
def bot_message(message):
    if message.chat.type == 'private':
        if message.text == "Выбрать уязвимость для сканирования":
            # Создание клавиатуры для выбора уязвимости
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
            item5 = types.KeyboardButton("SQl-инъекция")
            item6 = types.KeyboardButton("Межсайтовый скриптинг(XSS)")
            item7 = types.KeyboardButton("Межсайтовая подделка запроса(CSRF)")
            item8 = types.KeyboardButton("Недостаточная проверка входных данных")
            item9 = types.KeyboardButton("Недостаточная авторизация и аутентификация")
            item10 = types.KeyboardButton("Утечка информации")
            item11 = types.KeyboardButton("Недостаточная защита от переполнения буфера")
            back = types.KeyboardButton("Назад")
            markup.add(item5, item6, item7, item8, item9, item10, item11, back)
            bot.send_message(message.chat.id, 'Выбрать уязвимость для сканирования', reply_markup=markup)
        elif message.text == "SQl-инъекция":
            bot.send_message(message.chat.id, 'Введите URL сайта')
        elif message.text == "Помощь":
            # Отправка текста помощи
            help_text = """
            Привет! Я бот для сканирования уязвимостей на веб-страницах.

            Вот список доступных команд:
            /start - начать работу с ботом
            /help - отобразить это сообщение
            /scan_sql <URL> - сканировать указанную страницу на наличие SQL-инъекций

            Пример использования:
            /scan_sql https://example.com/page
            """
            bot.send_message(message.chat.id, help_text)
            # Создание клавиатуры для возврата назад
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
            item8 = types.KeyboardButton("Назад")
            markup.add(item8)
            bot.send_message(message.chat.id, 'Помощь', reply_markup=markup)
        elif message.text == "Рекомендации":
            # Создание клавиатуры для выбора уязвимости
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
            item5 = types.KeyboardButton("SQl-инъекция")
            item6 = types.KeyboardButton("Межсайтовый скриптинг(XSS)")
            item7 = types.KeyboardButton("Межсайтовая подделка запроса(CSRF)")
            item8 = types.KeyboardButton("Недостаточная проверка входных данных")
            item9 = types.KeyboardButton("Недостаточная авторизация и аутентификация")
            item10 = types.KeyboardButton("Утечка информации")
            item11 = types.KeyboardButton("Недостаточная защита от переполнения буфера")
            back = types.KeyboardButton("Назад")
            markup.add(item5, item6, item7, item8, item9, item10, item11, back)
            bot.send_message(message.chat.id, 'Рекомендации', reply_markup=markup)
        elif message.text == "Назад":
            # Создание клавиатуры для возврата назад
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
            item1 = types.KeyboardButton("Выбрать уязвимость для сканирования")
            item2 = types.KeyboardButton("Помощь")
            item3 = types.KeyboardButton("Рекомендации")
            item4 = types.KeyboardButton("Выход")
            markup.add(item1, item2, item3, item4)
            bot.send_message(message.chat.id, 'Назад', reply_markup=markup)
        elif message.text.startswith("http"):
            # Проверка корректности URL
            if not is_valid_url(message.text):
                bot.reply_to(message, "Некорректный URL. Пожалуйста, введите корректный URL.")
                return
            handle_scan(message)


def handle_scan(message):
    url = message.text.strip()
    if not url:
        bot.reply_to(message, "Использование: /scan_sql <URL>")
        return

    bot.reply_to(message, "Сканирую сайт на наличие SQL-инъекций...")

    try:
        start_time = time.time()
        method = "POST"
        analyzed_data, vulnerabilities = sqld.find_sql_injection(url, method)
        end_time = time.time()
        elapsed_time = end_time - start_time
        authentication_required = is_authentication_required(url)
        title, status_code, response_body = sqld.parse_url(url)

        if vulnerabilities:
            vulnerabilities_info = "\n".join(
                [f"{vuln_type}: {vuln_name}" for vuln_type, vuln_name in vulnerabilities.items()])
            recommendations = [sqld.get_injection_recommendation(injection_type) for injection_type in vulnerabilities]
            recommendation_text = "\n".join(recommendations)
            report = f"""------------------------------------Результаты------------------------------------
            
------------------------------------URL Метод------------------------------------
{url} 
{method}

------------------------------------Детали------------------------------------
Заголовок страницы: {title}
HTTP-статус код ответа: {status_code}

-------------------------Описание риска:-------------------------
{vulnerabilities_info}

-------------------------Рекомендации:-------------------------
{recommendation_text}

----------------------------Ссылки:----------------------------
Все URL-адреса, найденные сканером, включая дубликаты (доступно в течение 90 дней после даты сканирования)

---------------Информация о покрытии сканирования---------------
Список выполненных тестов (1/1)

---------------------Параметры сканирования---------------------
Цель: {url}
Тип сканирования: Light
Аутентификация: {'Требуется' if authentication_required else 'Не требуется'}

---------------------Статистика сканирования---------------------
Обнаружено уникальных точек инъекции: {len(vulnerabilities)}
URL-адресов проиндексировано: 1
Общее количество HTTP-запросов: 0
Среднее время до получения ответа: {elapsed_time:.2f} сек"""

        else:
            report = f"Уязвимостей не обнаружено."
        bot.send_message(message.chat.id, report)
        with open("report.txt", "w", encoding="utf-8") as file:
            file.write(report)
        with open("report.txt", "a", encoding="utf-8") as file:
            title, status_code, response_body = sqld.parse_url(url)
            file.write("\n\nЗаголовок страницы: {}\n".format(title))
            file.write("HTTP-статус код ответа: {}\n".format(status_code))
            file.write("Тело ответа на запрос: {}\n".format(response_body))
        with open("report.txt", "rb") as file:
            bot.send_document(message.chat.id, file)
        os.remove("report.txt")
    except Exception as e:
        logger.error(f"Ошибка при сканировании страницы: {str(e)}")
        bot.reply_to(message, f"Ошибка при сканировании страницы: {str(e)} Убедитесь, что вы ввели корректный URL.")


def is_valid_url(url):
    regex = re.compile(r"^https?://", re.IGNORECASE)
    return bool(regex.match(url))


bot.polling()