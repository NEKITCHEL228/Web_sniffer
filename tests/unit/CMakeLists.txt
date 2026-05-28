include(FetchContent)
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.5.2
)
FetchContent_MakeAvailable(Catch2)

file(GLOB PROJECT_TEST_HEADERS "${CMAKE_SOURCE_DIR}/include/*.h")
add_executable(unit_tests
    test_anomalydetector.cpp
    test_filemanager.cpp
    test_filterparser.cpp
    test_packet.cpp
    test_packetfactory.cpp
    test_sniffer.cpp
    test_snifferfacade.cpp
    test_statistics.cpp
)

set_target_properties(unit_tests PROPERTIES
    AUTOMOC ON
    AUTOUIC ON
    AUTORCC ON
)

target_link_libraries(unit_tests PRIVATE
    Catch2::Catch2WithMain
    Web_Sniffer_Core
    Qt6::Test
)

if(WIN32)
    target_include_directories(unit_tests PRIVATE ${NPCAP_SDK_PATH}/Include)
    target_link_directories(unit_tests PRIVATE ${NPCAP_SDK_PATH}/Lib/x64)
    target_link_libraries(unit_tests PRIVATE wpcap Packet)
    target_compile_definitions(unit_tests PRIVATE WPCAP HAVE_REMOTE)
else()
    if(PCAP_FOUND)
        target_include_directories(unit_tests PRIVATE ${PCAP_INCLUDE_DIRS})
        target_link_libraries(unit_tests PRIVATE ${PCAP_LIBRARIES})
    endif()
endif()

include(CTest)
include(Catch)
catch_discover_tests(unit_tests)
