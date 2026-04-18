vmp_add_placeholder_library(vmp_backend_llvm
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/backend/llvm_backend.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/llvm_backend.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_backend_llvm PUBLIC vmp_planner)
