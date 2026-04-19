add_library(vmp_runtime_vm1 STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/vm1.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/interpreter.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/bridge.cpp)
target_link_libraries(vmp_runtime_vm1 PUBLIC vmp_build_options vmp_runtime_audit vmp_runtime_strings)
target_link_libraries(vmp_runtime_vm1 PRIVATE vmp_arch_common)
if(VMP_WITH_JIT)
  target_link_libraries(vmp_runtime_vm1 PUBLIC vmp_runtime_jit)
endif()
target_include_directories(vmp_runtime_vm1 PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/arch/common/include)
