vmp_add_placeholder_library(vmp_loader_linux
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/loader/linux/linux_loader.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/linux_loader.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_loader_linux PUBLIC vmp_runtime_state vmp_runtime_audit)
