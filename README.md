# telegram-cache-decryption

Доработанная версия программы:

 - Не требует огромных зависимостей по типу PyQt5
 - Работает полностью на питоне, без модулей на C
 - Проставляет расширение файла автоматически
 - Выставляет у файлов корректную дату изменения чтобы можно было отсортировать
 - Грузит все ядра процессора

Для чего это нужно?
Можно посмотреть файлы которые лежат у вас на компьютере в кеше, например если картинку в чате отредактировали, или вас заблокировали в группе

Спасибо Bing чату без которого это бы не получилось сделать, с шифрованием самому разобраться невозможно

Установка:
```
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -U wheel pip

pip install -r requirements.txt
```

Запуск по умолчанию:

`python telegram-cache-decryption.py`

Если сторонний клиент:

`python telegram-cache-decryption.py -k "C:\Users\megapro17\AppData\Roaming\64Gram Desktop\tdata\key_datas" -c "C:\Users\megapro17\AppData\Roaming\64Gram Desktop\tdata\user_data"`

Задать выходную папку:

`python telegram-cache-decryption.py -o "C:\Users\megapro17\Desktop\telega"`
