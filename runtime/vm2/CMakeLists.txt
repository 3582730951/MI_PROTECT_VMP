add_library(vmp_runtime_vm2 STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/vm2.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/interpreter.cpp)
target_link_libraries(vmp_runtime_vm2 PUBLIC vmp_build_options vmp_runtime_audit vmp_runtime_strings vmp_runtime_vm1 vmp_runtime_cryptor)
target_link_libraries(vmp_runtime_vm2 PUBLIC vmp_runtime_env_integrity vmp_runtime_stack_probe)
if(VMP_WITH_JIT)
  target_link_libraries(vmp_runtime_vm2 PUBLIC vmp_runtime_jit)
endif()
target_include_directories(vmp_runtime_vm2 PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/runtime/vm1/include
  ${CMAKE_SOURCE_DIR}/runtime/cryptor/include
  ${CMAKE_SOURCE_DIR}/runtime/env_integrity/include
  ${CMAKE_SOURCE_DIR}/runtime/stack_probe/include)
