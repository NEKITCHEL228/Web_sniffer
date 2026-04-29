cmake_minimum_required(VERSION 3.16)
project(Web_Sniffer VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Gui Core)

file(GLOB_RECURSE PROJECT_HEADERS "include/*.h")

# Список исходных файлов
set(PROJECT_SOURCES
    src/main.cpp
    src/ui.cpp
    src/sniffer.cpp
    src/snifferfacade.cpp
    src/analyzer.cpp
    src/packet.cpp
    src/packetfactory.cpp
    src/statistics.cpp
    src/filemanager.cpp
    src/filterdialog.cpp
    src/filterstrategy.cpp
    resources.qrc
)

# Создание исполняемого файла
qt_add_executable(${PROJECT_NAME} MANUAL_FINALIZATION ${PROJECT_SOURCES} ${PROJECT_HEADERS})

# Пути к заголовочным файлам
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

#Подключаем библы
if(WIN32)
    # Попытка найти Npcap SDK
    set(NPCAP_SDK_PATH "C:/Npcap-SDK" CACHE PATH "Path to Npcap SDK")
    target_include_directories(${PROJECT_NAME} PRIVATE ${NPCAP_SDK_PATH}/Include)
    target_link_directories(${PROJECT_NAME} PRIVATE ${NPCAP_SDK_PATH}/Lib/x64)
    target_link_libraries(${PROJECT_NAME} PRIVATE wpcap Packet)
    target_compile_definitions(${PROJECT_NAME} PRIVATE WPCAP HAVE_REMOTE)
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE pcap)
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt6::Widgets
    Qt6::Gui
    Qt6::Core
)

qt_finalize_executable(${PROJECT_NAME})
