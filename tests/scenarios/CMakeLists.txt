file(GLOB PROJECT_TEST_HEADERS "${CMAKE_SOURCE_DIR}/include/*.h")
add_executable(scenario_1 scenario_1.cpp)
target_link_libraries(scenario_1 PRIVATE Web_Sniffer_Core Qt6::Widgets Qt6::Gui Qt6::Core Qt6::Network)
add_test(NAME scenario_1 COMMAND scenario_1)

add_executable(scenario_2 scenario_2.cpp)
target_link_libraries(scenario_2 PRIVATE Web_Sniffer_Core Qt6::Widgets Qt6::Gui Qt6::Core Qt6::Network)
add_test(NAME scenario_2 COMMAND scenario_2)

add_executable(scenario_3 scenario_3.cpp)
target_link_libraries(scenario_3 PRIVATE Web_Sniffer_Core Qt6::Widgets Qt6::Gui Qt6::Core Qt6::Network)
add_test(NAME scenario_3 COMMAND scenario_3)

add_executable(scenario_4 scenario_4.cpp)
target_link_libraries(scenario_4 PRIVATE Web_Sniffer_Core Qt6::Widgets Qt6::Gui Qt6::Core Qt6::Network)
add_test(NAME scenario_4 COMMAND scenario_4)

add_executable(scenario_5 scenario_5.cpp)
target_link_libraries(scenario_5 PRIVATE Web_Sniffer_Core Qt6::Widgets Qt6::Gui Qt6::Core Qt6::Network)
add_test(NAME scenario_5 COMMAND scenario_5)

if(WIN32)
    target_include_directories(scenario_1 PRIVATE ${NPCAP_SDK_PATH}/Include)
    target_link_directories(scenario_1 PRIVATE ${NPCAP_SDK_PATH}/Lib/x64)
    target_link_libraries(scenario_1 PRIVATE wpcap Packet)
    target_compile_definitions(scenario_1 PRIVATE WPCAP HAVE_REMOTE)

    target_include_directories(scenario_2 PRIVATE ${NPCAP_SDK_PATH}/Include)
    target_link_directories(scenario_2 PRIVATE ${NPCAP_SDK_PATH}/Lib/x64)
    target_link_libraries(scenario_2 PRIVATE wpcap Packet)
    target_compile_definitions(scenario_2 PRIVATE WPCAP HAVE_REMOTE)

    target_include_directories(scenario_3 PRIVATE ${NPCAP_SDK_PATH}/Include)
    target_link_directories(scenario_3 PRIVATE ${NPCAP_SDK_PATH}/Lib/x64)
    target_link_libraries(scenario_3 PRIVATE wpcap Packet)
    target_compile_definitions(scenario_3 PRIVATE WPCAP HAVE_REMOTE)

    target_include_directories(scenario_4 PRIVATE ${NPCAP_SDK_PATH}/Include)
    target_link_directories(scenario_4 PRIVATE ${NPCAP_SDK_PATH}/Lib/x64)
    target_link_libraries(scenario_4 PRIVATE wpcap Packet)
    target_compile_definitions(scenario_4 PRIVATE WPCAP HAVE_REMOTE)

    target_include_directories(scenario_5 PRIVATE ${NPCAP_SDK_PATH}/Include)
    target_link_directories(scenario_5 PRIVATE ${NPCAP_SDK_PATH}/Lib/x64)
    target_link_libraries(scenario_5 PRIVATE wpcap Packet)
    target_compile_definitions(scenario_5 PRIVATE WPCAP HAVE_REMOTE)
else()
    if(PCAP_FOUND)
        target_include_directories(scenario_1 PRIVATE ${PCAP_INCLUDE_DIRS})
        target_link_libraries(scenario_1 PRIVATE ${PCAP_LIBRARIES})

        target_include_directories(scenario_2 PRIVATE ${PCAP_INCLUDE_DIRS})
        target_link_libraries(scenario_2 PRIVATE ${PCAP_LIBRARIES})

        target_include_directories(scenario_3 PRIVATE ${PCAP_INCLUDE_DIRS})
        target_link_libraries(scenario_3 PRIVATE ${PCAP_LIBRARIES})

        target_include_directories(scenario_4 PRIVATE ${PCAP_INCLUDE_DIRS})
        target_link_libraries(scenario_4 PRIVATE ${PCAP_LIBRARIES})

        target_include_directories(scenario_5 PRIVATE ${PCAP_INCLUDE_DIRS})
        target_link_libraries(scenario_5 PRIVATE ${PCAP_LIBRARIES})
    endif()
endif()
