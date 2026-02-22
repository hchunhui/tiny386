# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

# Board selection: -DBOARD=<name> via cmake/idf.py, or BOARD env var, or default elecrow7.
# This must be set BEFORE include(project.cmake) so ESP-IDF reads the right sdkconfig.
if(NOT DEFINED BOARD)
    if(DEFINED ENV{BOARD})
        set(BOARD $ENV{BOARD})
    else()
        set(BOARD "elecrow7")
    endif()
endif()
# Use board-specific file as sdkconfig defaults.
# On a clean build (no sdkconfig present) ESP-IDF initialises sdkconfig from this file.
# When switching boards, delete sdkconfig (or run Full Clean) to trigger regeneration.
set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_SOURCE_DIR}/sdkconfig.${BOARD}")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tiny386)
