cmake_minimum_required(VERSION 3.16)

project(ad_transport
    VERSION 1.0
    LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Source files
set(INIH_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../prebuilt/inih/src/ini.c
)

set(AD_TRANSPORT_SOURCES
    src/ad_transport.c
    ${INIH_SRC}
)

# ---- CREATE THE TARGET FIRST ----
add_library(ad_transport SHARED ${AD_TRANSPORT_SOURCES})

# ---- ADD INCLUDE DIRS ----
target_include_directories(ad_transport PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../prebuilt/inih/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../ad_logger/include)

# ---- LINK LIBRARIES ----
target_link_libraries(ad_transport
    ${CMAKE_CURRENT_SOURCE_DIR}/../ad_logger/build/lib/libad_logger.so
    sqlite3
)

enable_testing()
add_subdirectory(tests)

