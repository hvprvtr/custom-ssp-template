# CMakeLists.txt — открытие проекта в VS 2026 через "Open Folder" (нативная CMake-поддержка).
# Собирает всё: DLL пакета (SSP) + тест + горячий загрузчик.
cmake_minimum_required(VERSION 3.20)
project(CustomSSP C)

# Статический CRT (/MT) — минимум зависимостей для загрузки внутрь lsass.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

# --- пакет: одна DLL = SSP, весь код в одном файле ---
add_library(CustomSSP SHARED
    src/CustomSSP.c
    src/CustomSSP.def)            # .def в списке исходников -> MSVC берёт его как список экспортов
target_compile_definitions(CustomSSP PRIVATE UNICODE _UNICODE)
target_link_libraries(CustomSSP PRIVATE kernel32)

# --- тест SSP (SSPI-хендшейк) ---
add_executable(ssp_test test/ssp_test.c)
target_compile_definitions(ssp_test PRIVATE SECURITY_WIN32)
target_link_libraries(ssp_test PRIVATE Secur32)

# --- горячий загрузчик (AddSecurityPackage в живой lsass) ---
add_executable(ssp_load tools/ssp_load.c)
target_compile_definitions(ssp_load PRIVATE SECURITY_WIN32)
target_link_libraries(ssp_load PRIVATE Secur32 Advapi32)
