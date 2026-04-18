vmp_add_placeholder_library(vmp_planner
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/planner/planner.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/planner.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_planner PUBLIC vmp_analyzer)
