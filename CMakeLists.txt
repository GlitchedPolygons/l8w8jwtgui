cmake_minimum_required(VERSION 3.5)

project(l8w8jwtgui VERSION 1.0.3 LANGUAGES CXX C)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(L8W8JWT_ENABLE_EDDSA "Build l8w8jwt with support for EdDSA (Ed25519) signing enabled." ON)

if (WIN32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -wd5105")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -wd5105")
endif()

find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets REQUIRED)

set(PROJECT_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/res/icons.qrc
        ${CMAKE_CURRENT_LIST_DIR}/src/main.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/mainwindow.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/mainwindow.h
        ${CMAKE_CURRENT_LIST_DIR}/src/mainwindow.ui
        ${CMAKE_CURRENT_LIST_DIR}/src/entropydialog.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/entropydialog.h
        ${CMAKE_CURRENT_LIST_DIR}/src/entropydialog.ui
)

set(ED25519_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/add_scalar.c
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/ed25519.h
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/fe.c
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/fe.h
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/fixedint.h
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/ge.c
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/ge.h
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/key_convert.c
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/key_exchange.c
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/keypair.c
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/precomp_data.h
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/sc.c
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/sc.h
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/seed.c
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/sha512.c
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/sha512.h
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/sign.c
    ${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src/verify.c
)

# Windows Icon
set(APP_ICON_RESOURCE_WINDOWS "${CMAKE_CURRENT_LIST_DIR}/img/winico.rc")

#  MacOS Icon
set(MACOSX_BUNDLE_ICON_FILE icon.icns)
set(APP_ICON_MACOSX ${CMAKE_CURRENT_LIST_DIR}/img/icon.icns)
set_source_files_properties(${APP_ICON_MACOSX} PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")

# Add the lib/l8w8jwt git submodule as a CMake subdirectory for easy integration
if (NOT TARGET l8w8jwt)
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt")
endif()

if (NOT TARGET mbedtls)
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/mbedtls")
endif()

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(l8w8jwtgui
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        ${ED25519_SOURCES}
        ${APP_ICON_MACOSX}
        ${APP_ICON_RESOURCE_WINDOWS}
    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET l8w8jwtgui APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(l8w8jwtgui SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(l8w8jwtgui
            ${PROJECT_SOURCES}
            ${APP_ICON_MACOSX}
            ${APP_ICON_RESOURCE_WINDOWS}
        )
    endif()
endif()

if (WIN32)
    target_compile_options(${PROJECT_NAME} PUBLIC /W3)
    add_compile_definitions("_CRT_SECURE_NO_WARNINGS=1")
endif ()

target_link_libraries(l8w8jwtgui
    PRIVATE Qt${QT_VERSION_MAJOR}::Widgets
    PRIVATE l8w8jwt
)

target_include_directories(l8w8jwtgui
    PRIVATE "${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/mbedtls/include"
    PRIVATE "${CMAKE_CURRENT_LIST_DIR}/lib/l8w8jwt/lib/ed25519/src"
)

set_target_properties(l8w8jwtgui PROPERTIES
    WIN32_EXECUTABLE true
    MACOSX_BUNDLE true
    MACOSX_BUNDLE_GUI_IDENTIFIER l8w8jwtgui.glitchedpolygons.com
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
)

add_custom_command(TARGET l8w8jwtgui
    POST_BUILD COMMAND ${CMAKE_COMMAND}
    -E copy ${CMAKE_CURRENT_LIST_DIR}/qss/theme.qss "${CMAKE_CURRENT_BINARY_DIR}/"
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(l8w8jwtgui)
endif()
