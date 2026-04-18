add_library(vmp_runtime_audit STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/audit.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/detector.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/reaction.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/placeholder.cpp)

target_link_libraries(vmp_runtime_audit PUBLIC vmp_build_options vmp_policy)
target_include_directories(vmp_runtime_audit PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/runtime/state/include)
