# pkcs7
Библиотека для формирования client_secret при подключении к ЕСИА(ECIA Единая система идентификации и аутентификации) через oAuth 2.0. Библиотека использует gogost реализацию GOST 3410 от http://www.gogost.cypherpunks.ru/. Инструкция по установки библиотеки на сайте автора.
## go mod
Для версии 5.9 необходимо использовать функцию замены в go mod файле.

    require go.cypherpunks.ru/gogost/v5 v5.9.0
    replace go.cypherpunks.ru/gogost/v5 => /path/to/gogost-5.9.0

и заменить пакеты с github.com/pedroalbanese/gogost на go.cypherpunks.ru/gogost/v5
