vmp_add_placeholder_library(vmp_runtime_state
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/runtime/state/state.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/state.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_runtime_state PUBLIC vmp_policy)
