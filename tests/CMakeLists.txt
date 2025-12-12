# ---- TEST SOURCE FILES ----
add_executable(ad_transport_tests
    test_main.cpp
    test_peer_table_db.cpp
    # Additional test source files can be added here
)

# ---- ADD INCLUDE DIRS ----
target_include_directories(ad_transport_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../prebuilt/inih/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../ad_logger/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../prebuilt/googletest/googletest/include
    # Additional include directories can be added here
)

# ---- IMPORT LIBRARIES START ----

add_library(libad_logger SHARED IMPORTED)
set_target_properties(libad_logger PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/../../ad_logger/build/lib/libad_logger.so"
)

add_library(gtest STATIC IMPORTED)
set_target_properties(gtest PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/../../../prebuilt/googletest/build/lib/libgtest.a"
)

add_library(gtest_main STATIC IMPORTED)
set_target_properties(gtest_main PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/../../../prebuilt/googletest/build/lib/libgtest_main.a"
)

# additional libraries can be added here

# ---- IMPORT LIBRARIES END ----

# ---- LINK LIBRARIES ----
target_link_libraries(ad_transport_tests PRIVATE
    sqlite3
    ad_transport
    libad_logger
    gtest
    pthread
)

add_test(NAME ad_transport_tests COMMAND ad_transport_tests)
