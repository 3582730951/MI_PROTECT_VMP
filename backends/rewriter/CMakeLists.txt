vmp_add_placeholder_library(vmp_backend_rewriter
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/backend/rewriter_backend.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/rewriter_backend.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_backend_rewriter PUBLIC vmp_planner)
