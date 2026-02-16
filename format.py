import argparse
import subprocess
import sys
import os, shutil


def check_formatting():
    """Проверка форматирования с помощью Black."""
    result = subprocess.run(["black", "--check", "."], capture_output=True, text=True)
    if result.returncode == 0:
        print("Файлы соответствуют стандартам форматирования.")
    else:
        print("Найдены проблемы с форматированием:")
        print(result.stdout)
        print(result.stderr)


def fix_formatting():
    """Исправление форматирования с помощью Black."""
    result = subprocess.run(["black", "."], capture_output=True, text=True)
    if result.returncode == 0:
        print("Форматирование успешно исправлено.")
    else:
        print("Произошла ошибка при исправлении форматирования:")
        print(result.stderr)


def clean_caches(path):
    """Очистка кешей Django-приложения."""
    for root, dirs, files in os.walk(path):
        # Удаление папки __pycache__
        if "__pycache__" in dirs:
            shutil.rmtree(os.path.join(root, "__pycache__"))
            print(f"Удалена папка: {os.path.join(root, '__pycache__')}")

        # Удаление файлов .pyc
        for file in files:
            if file.endswith(".pyc"):
                os.remove(os.path.join(root, file))
                print(f"Удален файл: {os.path.join(root, file)}")


def main():
    parser = argparse.ArgumentParser(
        description="Проверка и исправление форматирования Python файлов с помощью Black."
    )
    parser.add_argument(
        "-n",
        "--check",
        action="store_true",
        help="Проверка на соответствие форматирования",
    )
    parser.add_argument(
        "-i", "--fix", action="store_true", help="Исправление форматирования"
    )
    parser.add_argument("-c", "--clean", action="store_true", help="Очистка")
    args = parser.parse_args()

    if args.check and args.fix:
        print(
            "Ошибка: Укажите только один флаг: -n для проверки или -i для исправления."
        )
        sys.exit(1)

    if args.check:
        check_formatting()
    elif args.fix:
        fix_formatting()
    elif args.clean:
        clean_caches(os.getcwd())
    else:
        print("Ошибка: Необходимо указать флаг -n для проверки или -i для исправления.")
        sys.exit(0)


if __name__ == "__main__":
    main()
