vmp_add_placeholder_library(vmp_runtime_strings
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/runtime/strings/strings.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/strings.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_runtime_strings PUBLIC vmp_policy)
