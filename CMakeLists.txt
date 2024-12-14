cmake_minimum_required(VERSION 3.12)

project(wspp)

find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE SOURCES 
    src/*.cpp 
)

include_directories(
    "${PROJECT_SOURCE_DIR}/include/"
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} -pthread ${OPENSSL_LIBRARIES})
