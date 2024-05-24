import os


def convert_py_to_txt(py_file, output_dir):
    # Проверяем, существует ли указанный .py файл
    if not os.path.isfile(py_file):
        print(f"Файл {py_file} не найден.")
        return

    # Создаем имя для .txt файла
    base_name = os.path.basename(py_file)
    txt_file = os.path.join(output_dir, base_name.replace('.py', '.txt'))

    try:
        # Считываем содержимое .py файла
        with open(py_file, 'r', encoding='utf-8') as file:
            content = file.read()

        # Записываем содержимое в .txt файл
        with open(txt_file, 'w', encoding='utf-8') as file:
            file.write(content)

        print(f"Файл {py_file} успешно конвертирован в {txt_file}.")

    except Exception as e:
        print(f"Произошла ошибка при конвертации файла: {e}")


def main():
    # Указание имен файлов и директории
    files = ['scanner_v2.py', 'sql.py', 'scraper.py', 'xss.py', 'recommendations.py', 'idor.py','lfi.py', 'rfi.py', 'csrf.py']
    input_dir = 'F:\code\Diplom\Web_vuln_scanner'  # Замените на путь к вашей директории
    output_dir = os.path.join(input_dir, 'txt')

    # Проверяем и создаем директорию для txt файлов, если она не существует
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Конвертируем каждый файл
    for file in files:
        py_file = os.path.join(input_dir, file)
        convert_py_to_txt(py_file, output_dir)


# Запуск скрипта
if __name__ == "__main__":
    main()
