vmp_add_placeholder_library(vmp_analyzer
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/analyzer/analyzer.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/analyzer.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_analyzer PUBLIC vmp_policy)
