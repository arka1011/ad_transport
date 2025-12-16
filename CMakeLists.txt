cmake_minimum_required(VERSION 3.16)

project(ad_transport
    VERSION 1.0
    LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ---- SOURCES ----
set(INIH_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../prebuilt/inih/src/ini.c
)

add_library(ad_transport SHARED
    src/ad_transport.c
    ${INIH_SRC}
)

# ---- INCLUDE DIRS ----
target_include_directories(ad_transport
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../prebuilt/inih/include
)

# ---- LINK LIBRARIES ----
target_link_libraries(ad_transport
    PUBLIC
        ad_logger
        ad_tun
    PRIVATE
        sqlite3
)

enable_testing()
add_subdirectory(tests)
