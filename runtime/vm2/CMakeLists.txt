vmp_add_placeholder_library(vmp_runtime_vm2
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/runtime/vm2/vm2.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/vm2.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_runtime_vm2 PUBLIC vmp_planner)
