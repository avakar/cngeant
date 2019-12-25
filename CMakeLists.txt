cmake_minimum_required(VERSION 3.15)
project(cngeant)

add_executable(cngeant WIN32
    src/agent.cpp
    src/agent.h
    src/main.cpp
    src/main.manifest
    src/res.rc
    src/resource.h
    src/ssh_pack.cpp
    src/ssh_pack.h
    src/utils.cpp
    src/utils.h
    src/win32_utils.cpp
    src/win32_utils.h
    )
target_compile_features(cngeant PUBLIC cxx_std_17)
target_link_libraries(cngeant PUBLIC ncrypt.lib secur32.lib)
set_property(TARGET cngeant PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
