add_library(vmp_runtime_strings STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/strings.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/keyctx.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/aes256_ctr.cpp)
target_link_libraries(vmp_runtime_strings PUBLIC vmp_build_options vmp_policy vmp_runtime_audit)
target_include_directories(vmp_runtime_strings PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
