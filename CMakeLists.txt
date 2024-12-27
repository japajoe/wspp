cmake_minimum_required(VERSION 3.12)

project(wspp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WSPP_BUILD_WIN32 "Build support for Win32" OFF)

find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE SOURCES 
    src/*.cpp 
)

include_directories(
    "${PROJECT_SOURCE_DIR}/include/"
    ${OPENSSL_INCLUDE_DIR}
)

add_library(${PROJECT_NAME} SHARED ${SOURCES})

if(WSPP_BUILD_WIN32)
    message(STATUS "Building for Win32")
    target_link_libraries(${PROJECT_NAME} ws2_32 ${OPENSSL_LIBRARIES})
else()
    message(STATUS "Building for POSIX")
    message(${OPENSSL_LIBRARIES})
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
    install(TARGETS ${PROJECT_NAME} DESTINATION /usr/local/lib)
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION /usr/local/include/wspp)
endif()