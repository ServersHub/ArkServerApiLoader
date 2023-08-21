cmake_minimum_required(VERSION 3.26)
project(Loader)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 17)

add_compile_definitions(UNICODE)

add_executable(Loader main.cpp
        Inject.ixx
        Loader.ixx
        text.ixx)

include(FetchContent)
FetchContent_Declare(ztd.text
        GIT_REPOSITORY https://github.com/soasis/text.git
        GIT_SHALLOW    ON
        GIT_TAG        main)

FetchContent_MakeAvailable(ztd.text)

target_link_libraries(Loader PRIVATE ztd::text)