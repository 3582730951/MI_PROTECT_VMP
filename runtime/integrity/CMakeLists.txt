vmp_add_placeholder_library(vmp_runtime_integrity
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/runtime/integrity/integrity.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/integrity.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_runtime_integrity PUBLIC vmp_policy)
