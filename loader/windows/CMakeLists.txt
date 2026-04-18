vmp_add_placeholder_library(vmp_loader_windows
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/loader/windows/windows_loader.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/windows_loader.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_loader_windows PUBLIC vmp_runtime_state vmp_runtime_audit)
