vmp_add_placeholder_library(vmp_runtime_jit
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/runtime/jit/jit.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/jit.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_runtime_jit PUBLIC vmp_planner)
