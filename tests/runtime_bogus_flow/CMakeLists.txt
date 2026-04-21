function(vmp_add_runtime_bogus_flow_test target source)
  add_executable(${target} ${source})
  target_link_libraries(${target} PRIVATE
    vmp_runtime_obfuscation
    vmp_runtime_vm1
    vmp_runtime_vm2
    vmp_runtime_strings
    vmp_runtime_integrity
    vmp_runtime_audit)
  set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
  add_test(NAME ${target} COMMAND $<TARGET_FILE:${target}>)
  set_tests_properties(${target} PROPERTIES PASS_REGULAR_EXPRESSION "${target} OK")
endfunction()

vmp_add_runtime_bogus_flow_test(runtime_bogus_flow_vm1_rewriter
  ${CMAKE_CURRENT_SOURCE_DIR}/vm1_rewriter.cpp)
vmp_add_runtime_bogus_flow_test(runtime_bogus_flow_vm2_rewriter
  ${CMAKE_CURRENT_SOURCE_DIR}/vm2_rewriter.cpp)
vmp_add_runtime_bogus_flow_test(runtime_bogus_flow_vm1_runtime
  ${CMAKE_CURRENT_SOURCE_DIR}/vm1_runtime.cpp)
vmp_add_runtime_bogus_flow_test(runtime_bogus_flow_vm2_runtime
  ${CMAKE_CURRENT_SOURCE_DIR}/vm2_runtime.cpp)

add_library(vmp_runtime_vm1_bogus_handler_base STATIC
  ${CMAKE_SOURCE_DIR}/runtime/vm1/src/vm1.cpp
  ${CMAKE_SOURCE_DIR}/runtime/vm1/src/interpreter.cpp
  ${CMAKE_SOURCE_DIR}/runtime/vm1/src/bridge.cpp)
target_link_libraries(vmp_runtime_vm1_bogus_handler_base PUBLIC
  vmp_build_options
  vmp_runtime_audit
  vmp_runtime_strings
  vmp_runtime_cryptor
  vmp_runtime_env_integrity
  vmp_runtime_stack_probe
  vmp_runtime_jit
  vmp_runtime_obfuscation)
target_link_libraries(vmp_runtime_vm1_bogus_handler_base PRIVATE vmp_arch_common)
target_compile_definitions(vmp_runtime_vm1_bogus_handler_base PRIVATE
  VMP_WITH_JIT=0
  VMP_ENABLE_OPAQUE_HANDLER_PREDICATES=0
  VMP_ENABLE_BOGUS_HANDLER_FLOW=0)
target_include_directories(vmp_runtime_vm1_bogus_handler_base PUBLIC
  ${CMAKE_SOURCE_DIR}/runtime/vm1/include
  ${CMAKE_SOURCE_DIR}/arch/common/include
  ${CMAKE_SOURCE_DIR}/runtime/bridge/include
  ${CMAKE_SOURCE_DIR}/runtime/cryptor/include
  ${CMAKE_SOURCE_DIR}/runtime/env_integrity/include
  ${CMAKE_SOURCE_DIR}/runtime/integrity/include
  ${CMAKE_SOURCE_DIR}/runtime/jit/include
  ${CMAKE_SOURCE_DIR}/runtime/obfuscation/include
  ${CMAKE_SOURCE_DIR}/runtime/state/include
  ${CMAKE_SOURCE_DIR}/runtime/stack_probe/include)

add_library(vmp_runtime_vm2_bogus_handler_base STATIC
  ${CMAKE_SOURCE_DIR}/runtime/vm2/src/vm2.cpp
  ${CMAKE_SOURCE_DIR}/runtime/vm2/src/interpreter.cpp)
target_link_libraries(vmp_runtime_vm2_bogus_handler_base PUBLIC
  vmp_build_options
  vmp_runtime_audit
  vmp_runtime_strings
  vmp_runtime_vm1_bogus_handler_base
  vmp_runtime_cryptor
  vmp_runtime_env_integrity
  vmp_runtime_stack_probe
  vmp_runtime_jit
  vmp_runtime_obfuscation)
target_compile_definitions(vmp_runtime_vm2_bogus_handler_base PRIVATE
  VMP_WITH_JIT=0
  VMP_ENABLE_OPAQUE_HANDLER_PREDICATES=0
  VMP_ENABLE_BOGUS_HANDLER_FLOW=0)
target_include_directories(vmp_runtime_vm2_bogus_handler_base PUBLIC
  ${CMAKE_SOURCE_DIR}/runtime/vm2/include
  ${CMAKE_SOURCE_DIR}/runtime/vm1/include
  ${CMAKE_SOURCE_DIR}/runtime/bridge/include
  ${CMAKE_SOURCE_DIR}/runtime/cryptor/include
  ${CMAKE_SOURCE_DIR}/runtime/env_integrity/include
  ${CMAKE_SOURCE_DIR}/runtime/integrity/include
  ${CMAKE_SOURCE_DIR}/runtime/jit/include
  ${CMAKE_SOURCE_DIR}/runtime/obfuscation/include
  ${CMAKE_SOURCE_DIR}/runtime/state/include
  ${CMAKE_SOURCE_DIR}/runtime/stack_probe/include)

add_library(vmp_runtime_vm1_bogus_handler_obfuscated STATIC
  ${CMAKE_SOURCE_DIR}/runtime/vm1/src/vm1.cpp
  ${CMAKE_SOURCE_DIR}/runtime/vm1/src/interpreter.cpp
  ${CMAKE_SOURCE_DIR}/runtime/vm1/src/bridge.cpp)
target_link_libraries(vmp_runtime_vm1_bogus_handler_obfuscated PUBLIC
  vmp_build_options
  vmp_runtime_audit
  vmp_runtime_strings
  vmp_runtime_cryptor
  vmp_runtime_env_integrity
  vmp_runtime_stack_probe
  vmp_runtime_jit
  vmp_runtime_obfuscation)
target_link_libraries(vmp_runtime_vm1_bogus_handler_obfuscated PRIVATE vmp_arch_common)
target_compile_definitions(vmp_runtime_vm1_bogus_handler_obfuscated PRIVATE
  VMP_WITH_JIT=0
  VMP_ENABLE_OPAQUE_HANDLER_PREDICATES=1
  VMP_ENABLE_BOGUS_HANDLER_FLOW=1)
target_include_directories(vmp_runtime_vm1_bogus_handler_obfuscated PUBLIC
  ${CMAKE_SOURCE_DIR}/runtime/vm1/include
  ${CMAKE_SOURCE_DIR}/arch/common/include
  ${CMAKE_SOURCE_DIR}/runtime/bridge/include
  ${CMAKE_SOURCE_DIR}/runtime/cryptor/include
  ${CMAKE_SOURCE_DIR}/runtime/env_integrity/include
  ${CMAKE_SOURCE_DIR}/runtime/integrity/include
  ${CMAKE_SOURCE_DIR}/runtime/jit/include
  ${CMAKE_SOURCE_DIR}/runtime/obfuscation/include
  ${CMAKE_SOURCE_DIR}/runtime/state/include
  ${CMAKE_SOURCE_DIR}/runtime/stack_probe/include)

add_library(vmp_runtime_vm2_bogus_handler_obfuscated STATIC
  ${CMAKE_SOURCE_DIR}/runtime/vm2/src/vm2.cpp
  ${CMAKE_SOURCE_DIR}/runtime/vm2/src/interpreter.cpp)
target_link_libraries(vmp_runtime_vm2_bogus_handler_obfuscated PUBLIC
  vmp_build_options
  vmp_runtime_audit
  vmp_runtime_strings
  vmp_runtime_vm1_bogus_handler_obfuscated
  vmp_runtime_cryptor
  vmp_runtime_env_integrity
  vmp_runtime_stack_probe
  vmp_runtime_jit
  vmp_runtime_obfuscation)
target_compile_definitions(vmp_runtime_vm2_bogus_handler_obfuscated PRIVATE
  VMP_WITH_JIT=0
  VMP_ENABLE_OPAQUE_HANDLER_PREDICATES=1
  VMP_ENABLE_BOGUS_HANDLER_FLOW=1)
target_include_directories(vmp_runtime_vm2_bogus_handler_obfuscated PUBLIC
  ${CMAKE_SOURCE_DIR}/runtime/vm2/include
  ${CMAKE_SOURCE_DIR}/runtime/vm1/include
  ${CMAKE_SOURCE_DIR}/runtime/bridge/include
  ${CMAKE_SOURCE_DIR}/runtime/cryptor/include
  ${CMAKE_SOURCE_DIR}/runtime/env_integrity/include
  ${CMAKE_SOURCE_DIR}/runtime/integrity/include
  ${CMAKE_SOURCE_DIR}/runtime/jit/include
  ${CMAKE_SOURCE_DIR}/runtime/obfuscation/include
  ${CMAKE_SOURCE_DIR}/runtime/state/include
  ${CMAKE_SOURCE_DIR}/runtime/stack_probe/include)

add_executable(runtime_bogus_flow_handler_probe_base ${CMAKE_CURRENT_SOURCE_DIR}/handler_probe.cpp)
target_link_libraries(runtime_bogus_flow_handler_probe_base PRIVATE
  vmp_runtime_vm1_bogus_handler_base
  vmp_runtime_vm2_bogus_handler_base
  vmp_runtime_strings
  vmp_runtime_integrity
  vmp_runtime_audit)
set_target_properties(runtime_bogus_flow_handler_probe_base PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(runtime_bogus_flow_handler_probe_obfuscated ${CMAKE_CURRENT_SOURCE_DIR}/handler_probe.cpp)
target_link_libraries(runtime_bogus_flow_handler_probe_obfuscated PRIVATE
  vmp_runtime_vm1_bogus_handler_obfuscated
  vmp_runtime_vm2_bogus_handler_obfuscated
  vmp_runtime_strings
  vmp_runtime_integrity
  vmp_runtime_audit)
set_target_properties(runtime_bogus_flow_handler_probe_obfuscated PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_test(NAME runtime_bogus_flow_handler_objdump_growth
  COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/handler_objdump_growth.py
          $<TARGET_FILE:runtime_bogus_flow_handler_probe_base>
          $<TARGET_FILE:runtime_bogus_flow_handler_probe_obfuscated>)
set_tests_properties(runtime_bogus_flow_handler_objdump_growth PROPERTIES
  PASS_REGULAR_EXPRESSION "runtime_bogus_flow_handler_objdump_growth OK")
