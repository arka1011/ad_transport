# ---- TEST SOURCE FILES ----
add_executable(ad_transport_tests
    test_main.cpp
    test_peer_table_db.cpp
)

# ---- INCLUDE DIRS ----
target_include_directories(ad_transport_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../prebuilt/googletest/googletest/include
)

# ---- IMPORT GTEST ----
add_library(gtest STATIC IMPORTED)
set_target_properties(gtest PROPERTIES
    IMPORTED_LOCATION
        "${CMAKE_CURRENT_SOURCE_DIR}/../../../prebuilt/googletest/build/lib/libgtest.a"
)

add_library(gtest_main STATIC IMPORTED)
set_target_properties(gtest_main PROPERTIES
    IMPORTED_LOCATION
        "${CMAKE_CURRENT_SOURCE_DIR}/../../../prebuilt/googletest/build/lib/libgtest_main.a"
)

# ---- LINK LIBRARIES ----
target_link_libraries(ad_transport_tests PRIVATE
    ad_transport
    gtest
    gtest_main
    pthread
)

add_test(NAME ad_transport_tests COMMAND ad_transport_tests)

# ---- COPY CONFIG FILES ----
file(GLOB CONFIG_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/../test_configs/*
)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/configs)

foreach(CONFIG_FILE ${CONFIG_FILES})
    get_filename_component(CONFIG_NAME ${CONFIG_FILE} NAME)

    configure_file(
        ${CONFIG_FILE}
        ${CMAKE_CURRENT_BINARY_DIR}/configs/${CONFIG_NAME}
        COPYONLY
    )
endforeach()
