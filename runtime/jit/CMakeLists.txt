add_library(vmp_runtime_jit STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/jit.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/vm2_jit.cpp)
target_link_libraries(vmp_runtime_jit PUBLIC
  vmp_build_options
  vmp_runtime_audit
  vmp_runtime_strings
  vmp_runtime_state
  vmp_runtime_cryptor
  vmp_runtime_vm1)
if(VMP_WITH_VM2)
  target_link_libraries(vmp_runtime_jit PUBLIC vmp_runtime_vm2)
endif()
target_include_directories(vmp_runtime_jit PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/runtime/vm1/include
  ${CMAKE_SOURCE_DIR}/runtime/vm2/include
  ${CMAKE_SOURCE_DIR}/runtime/cryptor/include
  ${CMAKE_SOURCE_DIR}/runtime/strings/include
  ${CMAKE_SOURCE_DIR}/runtime/state/include)
