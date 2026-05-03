cmake_minimum_required(VERSION 3.16)

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR "In-source builds are not allowed. Please create a separate build directory (e.g., 'mkdir build && cd build') and run CMake from there.")
endif()

project(Web_Sniffer VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Gui Core Network)

file(GLOB_RECURSE PROJECT_HEADERS "include/*.h")

# Список исходных файлов
set(PROJECT_SOURCES
    ${PROJECT_HEADERS}
    src/filterparser.cpp
    src/main.cpp
    src/ui.cpp
    src/sniffer.cpp
    src/snifferfacade.cpp
    src/analyzer.cpp
    src/packet.cpp
    src/packetfactory.cpp
    src/statistics.cpp
    src/filemanager.cpp
    src/filterwidget.cpp
    src/filterstrategy.cpp
    resources.qrc
)

# Создание исполняемого файла
qt_add_executable(${PROJECT_NAME} MANUAL_FINALIZATION ${PROJECT_SOURCES})

# Пути к заголовочным файлам
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Подключение библиотек
if(WIN32)
    # Использование Npcap SDK для Windows
    set(NPCAP_SDK_PATH "C:/Npcap-SDK" CACHE PATH "Path to Npcap SDK")
    target_include_directories(${PROJECT_NAME} PRIVATE ${NPCAP_SDK_PATH}/Include)
    target_link_directories(${PROJECT_NAME} PRIVATE ${NPCAP_SDK_PATH}/Lib/x64)
    target_link_libraries(${PROJECT_NAME} PRIVATE wpcap Packet)
    target_compile_definitions(${PROJECT_NAME} PRIVATE WPCAP HAVE_REMOTE)
else()
    # Unix-подобные системы
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(PCAP libpcap)
    endif()

    if(NOT PCAP_FOUND)
        find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
        find_library(PCAP_LIBRARY NAMES pcap)
        if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
            set(PCAP_FOUND TRUE)
            set(PCAP_LIBRARIES ${PCAP_LIBRARY})
            set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
        endif()
    endif()

    if(PCAP_FOUND)
        target_include_directories(${PROJECT_NAME} PRIVATE ${PCAP_INCLUDE_DIRS})
        target_link_libraries(${PROJECT_NAME} PRIVATE ${PCAP_LIBRARIES})
    else()
        message(FATAL_ERROR "libpcap not found. Please install libpcap-dev or similar package.")
    endif()
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt6::Widgets
    Qt6::Gui
    Qt6::Core
    Qt6::Network
)

qt_finalize_executable(${PROJECT_NAME})
