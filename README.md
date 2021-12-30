# pkcs7
Библиотека для формирования client_secret при подключении к ЕСИА (ECIA Единая система идентификации и аутентификации) через oAuth 2.0. Библиотека использует gogost реализацию GOST 3410 от http://www.gogost.cypherpunks.ru/. Библиотека написана под конкретную задачу - подключение к ЕСИА (ESIA).
## private key
Файл приватного/открытого ключа создавался из папки контейнера(6 файлов header.key, masks.key, masks2.key, name.key, primary.key, primary2.key) с помощью утилиты get-cpcert (https://github.com/kov-serg/get-cpcert.git) 
