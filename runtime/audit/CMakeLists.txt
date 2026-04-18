vmp_add_placeholder_library(vmp_runtime_audit
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/runtime/audit/audit.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/audit.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_runtime_audit PUBLIC vmp_policy)
