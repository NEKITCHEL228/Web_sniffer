cmake_minimum_required(VERSION 3.16)

# 1. Задаёт имя проекта
project(Web_Sniffer VERSION 0.1 LANGUAGES CXX)

# 2. Находит компилятор C++ с флагами -std=c++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Настройки для автоматической работы Qt с макросами (MOC, UI, RCC)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# 3. Подключение сторонних библиотек (find_package)
find_package(Qt6 REQUIRED COMPONENTS Widgets LinguistTools)

# TODO: Для работы сниффера в будущем понадобится раскомментировать поиск PCAP
# find_package(PCAP REQUIRED)

# 4. Указывает список всех исходных файлов через set
set(PROJECT_SOURCES
    # Исходный код
    src/main.cpp
    src/ui.cpp
    src/sniffer.cpp
    src/snifferfacade.cpp
    src/packet.cpp
    src/analyzer.cpp
    src/filterstrategy.cpp
    src/statistics.cpp
    src/filemanager.cpp

    # Заголовочные файлы (теперь AUTOMOC их увидит)
    include/ui.h
    include/sniffer.h
    include/snifferfacade.h
    include/packet.h
    include/analyzer.h
    include/filterstrategy.h
    include/statistics.h
    include/filemanager.h

    # Ресурсы (иконки)
    resources.qrc
)

# 5. Объявляет исполняемый файл
qt_add_executable(${PROJECT_NAME} MANUAL_FINALIZATION ${PROJECT_SOURCES})

# 6. Подключает заголовочные файлы через target_include_directories (Требование ТЗ!)
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 7. Линковка библиотек (target_link_libraries)
target_link_libraries(${PROJECT_NAME} PRIVATE Qt6::Widgets)

# Локализация (если нужна)
set(TS_FILES Web_Sniffer_ru_RU.ts)
qt_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})

# Финализация для Qt6
qt_finalize_executable(${PROJECT_NAME})
