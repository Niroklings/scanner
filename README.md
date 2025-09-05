# File Scanner Utility
Утилита для рекурсивного сканирования файловых директорий с целью обнаружения вредоносных файлов по их MD5 хешам.
## Возможности
- Рекурсивное сканирование директорий с заходом во вложенные папки

- Определение вредоносных файлов по MD5 хешам

- Поддержка больших файлов (работа с файлами больше объема оперативной памяти)

- Детальное логирование результатов сканирования

- Консольный отчет со статистикой выполнения

- Кросс-платформенная работа (macOS, Windows, Linux)

- Модульная архитектура (EXE + DLL/dylib)
## Установка и сборка
### Требования
- C++17 compatible compiler 

- CMake 3.10+

- Google Test 
### Сборка на macOS/Linux
```bash
mkdir build
cd build

cmake ..

make

make test
```
### Сборка на Windows
```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```
## Использование
### Базовый запуск
```bash
./scanner --base <base.csv> --log <report.log> --path <directory>
```
### Параметры командной строки
- --base - Путь к CSV файлу с базой вредоносных хешей

- --log - Путь к файлу для записи логов сканирования

- --path - Директория для сканирования

- --help - Показать справку по использованию
### Пример запуска
```bash
./scanner --base base.csv --log scan_results.log --path /Users/user/documents
```
## Формат CSV базы хешей
CSV файл должен содержать строки в формате:
```
MD5_HASH;VERDICT_NAME
```
Пример содержимого base.csv
```
a9963513d093ffb2bc7ceb9807771ad4;Exploit
ac6204ffeb36d2320e52f1d551cfa370;Dropper
8ee70903f43b227eeb971262268af5a8;Downloader
```
## Формат отчета
### Консольный вывод
```
=== SCAN REPORT ===
Total files processed: 156
Malicious files found: 3  
Errors encountered: 2
Scan duration: 245 ms

WARNING: 3 malicious files detected!
See detailed log: scan_report.log
```
### Лог файл
```
Scan Log
========

File: /path/to/malicious.exe
Hash: a9963513d093ffb2bc7ceb9807771ad4
Verdict: Exploit
----------------------------------------
File: /path/to/suspicious.dll  
Hash: ac6204ffeb36d2320e52f1d551cfa370
Verdict: Dropper
----------------------------------------
```
## Архитектура
### Компоненты системы
```
scanner/
├── src/main.cpp              #консольный интерфейс
├── src/Scanner.cpp          #основная логика сканирования
├── include/Scanner.h        #интерфейс сканера
├── lib/MD5.cpp             #реализация MD5 хешера
├── include/MD5.h           #интерфейс MD5
└── scannerlib/             #динамическая библиотека
    └── src/ScannerLib.cpp  #С-интерфейс для DLL
```
### Модульная структура
- - Исполняемый файл (scanner) - Консольный интерфейс, парсинг аргументов

Динамическая библиотека (ScannerLib) - Основная логика сканирования

- MD5 хешер - Кросс-платформенная реализация MD5
##  Обработка ошибок
Утилита обрабатывает следующие типы ошибок:

- Отсутствие прав доступа к файлам

- Некорректные пути директорий

- Поврежденные CSV файлы

- Ошибки ввода-вывода
## Производительность
- Многопоточная обработка файлов

- Буферизированное чтение больших файлов

- Оптимизированный алгоритм хеширования

- Минимизация overhead при рекурсивном обходе