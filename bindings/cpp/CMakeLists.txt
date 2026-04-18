vmp_add_placeholder_library(vmp_bindings_cpp
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/bindings/cpp/plugin.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/plugin.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_bindings_cpp PUBLIC vmp_policy)
