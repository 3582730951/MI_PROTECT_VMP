find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(VMP_TEST_BIN_SUFFIX "")
if(WIN32)
  set(VMP_TEST_BIN_SUFFIX ".exe")
endif()

set(VMP_POLICY_FIXTURES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/policy/examples")
set(VMP_AUDIT_FIXTURES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/audit")
set(VMP_BINDINGS_CPP_FIXTURES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/bindings_cpp")

function(vmp_unset_ci_polluters test_name)
  set_tests_properties(${test_name} PROPERTIES
    ENVIRONMENT_MODIFICATION "CARGO_HOME=unset:;CARGO_BUILD_OFFLINE=unset:;VMP_DISABLE_CLANG_PLUGIN=unset:")
endfunction()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/dummy_test.py ${CMAKE_CURRENT_BINARY_DIR}/dummy_test.py COPYONLY)

add_executable(policy_cpp_test ${CMAKE_CURRENT_SOURCE_DIR}/policy/policy_cpp_test.cpp)
target_link_libraries(policy_cpp_test PRIVATE vmp_policy)
target_compile_definitions(policy_cpp_test PRIVATE
  VMP_POLICY_FIXTURES_DEFAULT_DIR="${VMP_POLICY_FIXTURES_DIR}")

add_executable(policy_cpp_summary ${CMAKE_CURRENT_SOURCE_DIR}/policy/policy_cpp_summary.cpp)
target_link_libraries(policy_cpp_summary PRIVATE vmp_policy)
target_compile_definitions(policy_cpp_summary PRIVATE
  VMP_POLICY_FIXTURES_DEFAULT_DIR="${VMP_POLICY_FIXTURES_DIR}")

add_test(NAME dummy_python_smoke
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/dummy_test.py)

add_test(NAME policy_cpp_test
  COMMAND policy_cpp_test)
set_tests_properties(policy_cpp_test PROPERTIES
  ENVIRONMENT "VMP_POLICY_FIXTURES_DIR=${VMP_POLICY_FIXTURES_DIR}")

add_test(NAME vmp_protect_good_policy
  COMMAND $<TARGET_FILE:vmp-protect> --policy ${CMAKE_CURRENT_SOURCE_DIR}/policy/examples/good.json)
set_tests_properties(vmp_protect_good_policy PROPERTIES PASS_REGULAR_EXPRESSION "OK: policy loaded, 2 entries, schema=v1")

add_test(NAME vmp_protect_bad_policy
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/policy/assert_bad_policy.py $<TARGET_FILE:vmp-protect> ${CMAKE_CURRENT_SOURCE_DIR}/policy/examples/bad_vm_func_native.json)
set_tests_properties(vmp_protect_bad_policy PROPERTIES PASS_REGULAR_EXPRESSION "bad policy rejected as expected")

add_test(NAME vmp_protect_dump_schema
  COMMAND $<TARGET_FILE:vmp-protect> --dump-schema)
set_tests_properties(vmp_protect_dump_schema PROPERTIES PASS_REGULAR_EXPRESSION "language_origin")

add_executable(audit_cpp_test ${CMAKE_CURRENT_SOURCE_DIR}/audit/audit_cpp_test.cpp)
target_link_libraries(audit_cpp_test PRIVATE vmp_runtime_audit nlohmann_json::nlohmann_json)
target_compile_definitions(audit_cpp_test PRIVATE
  VMP_AUDIT_FIXTURES_DEFAULT_DIR="${VMP_AUDIT_FIXTURES_DIR}")
set_target_properties(audit_cpp_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(audit_cpp_format ${CMAKE_CURRENT_SOURCE_DIR}/audit/audit_cpp_format.cpp)
target_link_libraries(audit_cpp_format PRIVATE vmp_runtime_audit nlohmann_json::nlohmann_json)
set_target_properties(audit_cpp_format PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_test(NAME audit_cpp_test
  COMMAND $<TARGET_FILE:audit_cpp_test>)
set_tests_properties(audit_cpp_test PROPERTIES PASS_REGULAR_EXPRESSION "audit_cpp_test OK")

add_test(NAME cross_language_golden
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/audit/compare_cpp_rust_audit.py $<TARGET_FILE:audit_cpp_format> ${CMAKE_CURRENT_SOURCE_DIR}/audit/golden_record.json ${CMAKE_SOURCE_DIR})
set_tests_properties(cross_language_golden PROPERTIES
  PASS_REGULAR_EXPRESSION "cross language audit golden OK"
  SKIP_REGULAR_EXPRESSION "cross language audit golden SKIPPED")
vmp_unset_ci_polluters(cross_language_golden)

add_test(NAME vmp_protect_detector_selftest
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/audit/assert_detector_selftest.py $<TARGET_FILE:vmp-protect> ${CMAKE_BINARY_DIR}/tests/detector_selftest.log)
set_tests_properties(vmp_protect_detector_selftest PROPERTIES PASS_REGULAR_EXPRESSION "detector selftest OK")

# bindings/cpp tests
set(VMP_CPP_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/bindings/cpp/include)
set(VMP_CPP_SAMPLE_C ${CMAKE_CURRENT_SOURCE_DIR}/bindings_cpp/sample_c.c)
set(VMP_CPP_SAMPLE_CPP ${CMAKE_CURRENT_SOURCE_DIR}/bindings_cpp/sample_cpp.cpp)
set(VMP_CPP_EXPECTED_C ${CMAKE_CURRENT_SOURCE_DIR}/bindings_cpp/expected_c.json)
set(VMP_CPP_EXPECTED_CPP_PLUGIN ${CMAKE_CURRENT_SOURCE_DIR}/bindings_cpp/expected_cpp_plugin.json)
set(VMP_CPP_EXPECTED_CPP_FALLBACK ${CMAKE_CURRENT_SOURCE_DIR}/bindings_cpp/expected_cpp_fallback.json)
set(VMP_CPP_COMPARE ${CMAKE_CURRENT_SOURCE_DIR}/bindings_cpp/compare_policy_json.py)
set(VMP_CPP_ASSERT_EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bindings_cpp/assert_exists.py)

add_test(NAME bindings_cpp_collect_c
  COMMAND $<TARGET_FILE:vmp-clang> -c ${VMP_CPP_SAMPLE_C} -I ${VMP_CPP_INCLUDE_DIR} --vmp-collect=${CMAKE_BINARY_DIR}/tests/sample_c.policy.json -o ${CMAKE_BINARY_DIR}/tests/sample_c.o)
add_test(NAME bindings_cpp_collect_c_compare
  COMMAND ${Python3_EXECUTABLE} ${VMP_CPP_COMPARE} ${CMAKE_BINARY_DIR}/tests/sample_c.policy.json ${VMP_CPP_EXPECTED_C})
set_tests_properties(bindings_cpp_collect_c_compare PROPERTIES DEPENDS bindings_cpp_collect_c PASS_REGULAR_EXPRESSION "policy json equal")
vmp_unset_ci_polluters(bindings_cpp_collect_c)
vmp_unset_ci_polluters(bindings_cpp_collect_c_compare)

add_test(NAME bindings_cpp_collect_cpp
  COMMAND $<TARGET_FILE:vmp-clang++> -std=c++17 -c ${VMP_CPP_SAMPLE_CPP} -I ${VMP_CPP_INCLUDE_DIR} --vmp-collect=${CMAKE_BINARY_DIR}/tests/sample_cpp.policy.json -o ${CMAKE_BINARY_DIR}/tests/sample_cpp.o)
if(VMP_BINDINGS_CPP_HAVE_CLANG_PLUGIN)
  add_test(NAME bindings_cpp_collect_cpp_compare
    COMMAND ${Python3_EXECUTABLE} ${VMP_CPP_COMPARE} ${CMAKE_BINARY_DIR}/tests/sample_cpp.policy.json ${VMP_CPP_EXPECTED_CPP_PLUGIN})
else()
  add_test(NAME bindings_cpp_collect_cpp_compare
    COMMAND ${Python3_EXECUTABLE} ${VMP_CPP_COMPARE} ${CMAKE_BINARY_DIR}/tests/sample_cpp.policy.json ${VMP_CPP_EXPECTED_CPP_FALLBACK})
endif()
set_tests_properties(bindings_cpp_collect_cpp_compare PROPERTIES DEPENDS bindings_cpp_collect_cpp PASS_REGULAR_EXPRESSION "policy json equal")
vmp_unset_ci_polluters(bindings_cpp_collect_cpp)
vmp_unset_ci_polluters(bindings_cpp_collect_cpp_compare)

add_test(NAME bindings_cpp_collect_cpp_fallback
  COMMAND ${CMAKE_COMMAND} -E env VMP_DISABLE_CLANG_PLUGIN=1 $<TARGET_FILE:vmp-clang++> -std=c++17 -c ${VMP_CPP_SAMPLE_CPP} -I ${VMP_CPP_INCLUDE_DIR} --vmp-collect=${CMAKE_BINARY_DIR}/tests/sample_cpp_fallback.policy.json -o ${CMAKE_BINARY_DIR}/tests/sample_cpp_fallback.o)
add_test(NAME bindings_cpp_collect_cpp_fallback_compare
  COMMAND ${Python3_EXECUTABLE} ${VMP_CPP_COMPARE} ${CMAKE_BINARY_DIR}/tests/sample_cpp_fallback.policy.json ${VMP_CPP_EXPECTED_CPP_FALLBACK})
set_tests_properties(bindings_cpp_collect_cpp_fallback_compare PROPERTIES DEPENDS bindings_cpp_collect_cpp_fallback PASS_REGULAR_EXPRESSION "policy json equal")
vmp_unset_ci_polluters(bindings_cpp_collect_cpp_fallback)
vmp_unset_ci_polluters(bindings_cpp_collect_cpp_fallback_compare)

add_test(NAME bindings_cpp_header_compile_clang_c
  COMMAND clang -c ${VMP_CPP_SAMPLE_C} -I ${VMP_CPP_INCLUDE_DIR} -o ${CMAKE_BINARY_DIR}/tests/header_clang_c.o)
add_test(NAME bindings_cpp_header_compile_clang_cpp
  COMMAND clang++ -std=c++17 -c ${VMP_CPP_SAMPLE_CPP} -I ${VMP_CPP_INCLUDE_DIR} -o ${CMAKE_BINARY_DIR}/tests/header_clang_cpp.o)
add_test(NAME bindings_cpp_header_compile_gcc_c
  COMMAND gcc -c ${VMP_CPP_SAMPLE_C} -I ${VMP_CPP_INCLUDE_DIR} -o ${CMAKE_BINARY_DIR}/tests/header_gcc_c.o)
add_test(NAME bindings_cpp_header_compile_gcc_cpp
  COMMAND g++ -std=c++17 -c ${VMP_CPP_SAMPLE_CPP} -I ${VMP_CPP_INCLUDE_DIR} -o ${CMAKE_BINARY_DIR}/tests/header_gcc_cpp.o)
if(MSVC)
  add_test(NAME bindings_cpp_header_compile_msvc_cpp
    COMMAND cl /nologo /std:c++17 /c ${VMP_CPP_SAMPLE_CPP} /I ${VMP_CPP_INCLUDE_DIR} /Fo${CMAKE_BINARY_DIR}/tests/header_msvc_cpp.obj)
endif()

add_test(NAME bindings_cpp_vmp_clang_passthrough
  COMMAND $<TARGET_FILE:vmp-clang> -c ${VMP_CPP_SAMPLE_C} -I ${VMP_CPP_INCLUDE_DIR} -o ${CMAKE_BINARY_DIR}/tests/passthrough_c.o)
add_test(NAME bindings_cpp_vmp_clang_passthrough_exists
  COMMAND ${Python3_EXECUTABLE} ${VMP_CPP_ASSERT_EXISTS} ${CMAKE_BINARY_DIR}/tests/passthrough_c.o)
set_tests_properties(bindings_cpp_vmp_clang_passthrough_exists PROPERTIES DEPENDS bindings_cpp_vmp_clang_passthrough PASS_REGULAR_EXPRESSION "exists:")

# bindings/rust tests
set(VMP_RUST_SAMPLE_MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/bindings_rust/sample/Cargo.toml)
set(VMP_RUST_EXPECTED ${CMAKE_CURRENT_SOURCE_DIR}/bindings_rust/expected.json)
set(VMP_RUST_COMPARE ${CMAKE_CURRENT_SOURCE_DIR}/bindings_rust/compare_policy_json.py)
set(VMP_RUST_PARITY_COMPARE ${CMAKE_CURRENT_SOURCE_DIR}/bindings_rust/compare_parity.py)
set(VMP_RUST_BASE_POLICY ${CMAKE_CURRENT_SOURCE_DIR}/bindings_rust/base_policy.json)
set(VMP_RUST_POLICY_OUT ${CMAKE_BINARY_DIR}/tests/demo_sample_rust.policy.json)
set(VMP_RUST_MERGED_OUT ${CMAKE_BINARY_DIR}/tests/demo_sample_rust_merged.policy.json)
set(VMP_RUST_PARITY_C ${CMAKE_CURRENT_SOURCE_DIR}/bindings_rust/parity_c/sample.c)

add_test(NAME bindings_rust_demo_build
  COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR} cargo build -p demo_sample)
add_test(NAME bindings_rust_collect
  COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR} cargo run -p vmp-rust-collect -- --target-dir ${CMAKE_SOURCE_DIR}/target --policy-out ${VMP_RUST_POLICY_OUT})
set_tests_properties(bindings_rust_collect PROPERTIES DEPENDS bindings_rust_demo_build PASS_REGULAR_EXPRESSION "vmp-rust-collect OK entries=5")
add_test(NAME bindings_rust_collect_compare
  COMMAND ${Python3_EXECUTABLE} ${VMP_RUST_COMPARE} ${VMP_RUST_POLICY_OUT} ${VMP_RUST_EXPECTED})
set_tests_properties(bindings_rust_collect_compare PROPERTIES DEPENDS bindings_rust_collect PASS_REGULAR_EXPRESSION "policy json equal")

add_test(NAME bindings_rust_parity_c_collect
  COMMAND $<TARGET_FILE:vmp-clang> -c ${VMP_RUST_PARITY_C} -I ${VMP_CPP_INCLUDE_DIR} --vmp-collect=${CMAKE_BINARY_DIR}/tests/bindings_rust_parity_c.json -o ${CMAKE_BINARY_DIR}/tests/bindings_rust_parity_c.o)
add_test(NAME bindings_rust_parity_compare
  COMMAND ${Python3_EXECUTABLE} ${VMP_RUST_PARITY_COMPARE} ${CMAKE_BINARY_DIR}/tests/bindings_rust_parity_c.json ${VMP_RUST_POLICY_OUT})
set_tests_properties(bindings_rust_parity_compare PROPERTIES DEPENDS "bindings_rust_parity_c_collect;bindings_rust_collect" PASS_REGULAR_EXPRESSION "rust/c parity OK")

add_test(NAME vmp_protect_rust_merge
  COMMAND $<TARGET_FILE:vmp-protect> --policy ${VMP_RUST_BASE_POLICY} --rust-target-dir ${CMAKE_SOURCE_DIR}/target --emit-policy-json ${VMP_RUST_MERGED_OUT} --validate-only)
set_tests_properties(vmp_protect_rust_merge PROPERTIES DEPENDS bindings_rust_demo_build PASS_REGULAR_EXPRESSION "OK: policy loaded, 5 entries, schema=v1")
add_test(NAME vmp_protect_rust_merge_compare
  COMMAND ${Python3_EXECUTABLE} ${VMP_RUST_COMPARE} ${VMP_RUST_MERGED_OUT} ${VMP_RUST_EXPECTED})
set_tests_properties(vmp_protect_rust_merge_compare PROPERTIES DEPENDS vmp_protect_rust_merge PASS_REGULAR_EXPRESSION "policy json equal")

vmp_unset_ci_polluters(bindings_rust_demo_build)
vmp_unset_ci_polluters(bindings_rust_collect)
vmp_unset_ci_polluters(bindings_rust_collect_compare)
vmp_unset_ci_polluters(bindings_rust_parity_c_collect)
vmp_unset_ci_polluters(bindings_rust_parity_compare)
vmp_unset_ci_polluters(vmp_protect_rust_merge)
vmp_unset_ci_polluters(vmp_protect_rust_merge_compare)


# runtime/strings tests
add_executable(strings_crypto_vectors ${CMAKE_CURRENT_SOURCE_DIR}/strings/crypto_vectors.cpp)
target_link_libraries(strings_crypto_vectors PRIVATE vmp_runtime_strings vmp_policy)
set_target_properties(strings_crypto_vectors PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(strings_transient_view_zeroization ${CMAKE_CURRENT_SOURCE_DIR}/strings/transient_view_zeroization.cpp)
target_link_libraries(strings_transient_view_zeroization PRIVATE vmp_runtime_strings vmp_policy)
set_target_properties(strings_transient_view_zeroization PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(strings_concurrency_8_threads ${CMAKE_CURRENT_SOURCE_DIR}/strings/concurrency_8_threads.cpp)
target_link_libraries(strings_concurrency_8_threads PRIVATE vmp_runtime_strings vmp_policy)
set_target_properties(strings_concurrency_8_threads PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(strings_pool_corruption_detected ${CMAKE_CURRENT_SOURCE_DIR}/strings/pool_corruption_detected.cpp)
target_link_libraries(strings_pool_corruption_detected PRIVATE vmp_runtime_strings vmp_runtime_audit vmp_policy)
set_target_properties(strings_pool_corruption_detected PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_test(NAME strings_crypto_vectors COMMAND $<TARGET_FILE:strings_crypto_vectors>)
set_tests_properties(strings_crypto_vectors PROPERTIES PASS_REGULAR_EXPRESSION "crypto_vectors OK")
add_test(NAME strings_transient_view_zeroization COMMAND $<TARGET_FILE:strings_transient_view_zeroization>)
set_tests_properties(strings_transient_view_zeroization PROPERTIES PASS_REGULAR_EXPRESSION "transient_view_zeroization OK")
add_test(NAME strings_concurrency_8_threads COMMAND $<TARGET_FILE:strings_concurrency_8_threads>)
set_tests_properties(strings_concurrency_8_threads PROPERTIES PASS_REGULAR_EXPRESSION "concurrency_8_threads OK")
add_test(NAME strings_pool_corruption_detected COMMAND $<TARGET_FILE:strings_pool_corruption_detected>)
set_tests_properties(strings_pool_corruption_detected PROPERTIES PASS_REGULAR_EXPRESSION "pool_corruption_detected OK")

# runtime/vm1 tests
add_executable(vm1_asm_round_trip ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1/vm1_asm_round_trip.cpp)
target_link_libraries(vm1_asm_round_trip PRIVATE vmp_runtime_vm1 vmp_runtime_audit)
set_target_properties(vm1_asm_round_trip PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm1_arith_ops ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1/vm1_arith_ops.cpp)
target_link_libraries(vm1_arith_ops PRIVATE vmp_runtime_vm1 vmp_runtime_audit)
set_target_properties(vm1_arith_ops PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm1_control_flow ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1/vm1_control_flow.cpp)
target_link_libraries(vm1_control_flow PRIVATE vmp_runtime_vm1 vmp_runtime_audit)
set_target_properties(vm1_control_flow PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm1_call_ret ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1/vm1_call_ret.cpp)
target_link_libraries(vm1_call_ret PRIVATE vmp_runtime_vm1 vmp_runtime_audit)
set_target_properties(vm1_call_ret PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm1_cross_domain_call ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1/vm1_cross_domain_call.cpp)
target_link_libraries(vm1_cross_domain_call PRIVATE vmp_runtime_vm1 vmp_runtime_audit)
set_target_properties(vm1_cross_domain_call PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm1_exceptions ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1/vm1_exceptions.cpp)
target_link_libraries(vm1_exceptions PRIVATE vmp_runtime_vm1 vmp_runtime_audit)
set_target_properties(vm1_exceptions PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm1_breakpoint_event ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1/vm1_breakpoint_event.cpp)
target_link_libraries(vm1_breakpoint_event PRIVATE vmp_runtime_vm1 vmp_runtime_audit)
set_target_properties(vm1_breakpoint_event PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm1_bench ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1/bench/vm1_bench.cpp)
target_link_libraries(vm1_bench PRIVATE vmp_runtime_vm1 vmp_runtime_audit)
set_target_properties(vm1_bench PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_test(NAME vm1_asm_round_trip COMMAND $<TARGET_FILE:vm1_asm_round_trip>)
set_tests_properties(vm1_asm_round_trip PROPERTIES PASS_REGULAR_EXPRESSION "vm1_asm_round_trip OK")
add_test(NAME vm1_arith_ops COMMAND $<TARGET_FILE:vm1_arith_ops>)
set_tests_properties(vm1_arith_ops PROPERTIES PASS_REGULAR_EXPRESSION "vm1_arith_ops OK")
add_test(NAME vm1_control_flow COMMAND $<TARGET_FILE:vm1_control_flow>)
set_tests_properties(vm1_control_flow PROPERTIES PASS_REGULAR_EXPRESSION "vm1_control_flow OK")
add_test(NAME vm1_call_ret COMMAND $<TARGET_FILE:vm1_call_ret>)
set_tests_properties(vm1_call_ret PROPERTIES PASS_REGULAR_EXPRESSION "vm1_call_ret OK")
add_test(NAME vm1_cross_domain_call COMMAND $<TARGET_FILE:vm1_cross_domain_call>)
set_tests_properties(vm1_cross_domain_call PROPERTIES PASS_REGULAR_EXPRESSION "vm1_cross_domain_call OK")
add_test(NAME vm1_exceptions COMMAND $<TARGET_FILE:vm1_exceptions>)
set_tests_properties(vm1_exceptions PROPERTIES PASS_REGULAR_EXPRESSION "vm1_exceptions OK")
add_test(NAME vm1_breakpoint_event COMMAND $<TARGET_FILE:vm1_breakpoint_event>)
set_tests_properties(vm1_breakpoint_event PROPERTIES PASS_REGULAR_EXPRESSION "vm1_breakpoint_event OK")
add_test(NAME vm1_bench COMMAND $<TARGET_FILE:vm1_bench>)
set_tests_properties(vm1_bench PROPERTIES PASS_REGULAR_EXPRESSION "vm1_bench nop_ms=")

add_test(NAME vmp_vm1_asm_fib20
  COMMAND $<TARGET_FILE:vmp-vm1-asm> ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1/fixtures/fib20.vm1s ${CMAKE_BINARY_DIR}/tests/fib20.vm1)
set_tests_properties(vmp_vm1_asm_fib20 PROPERTIES PASS_REGULAR_EXPRESSION "assembled")


add_executable(vm1_load_transient_string_integration ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1/strings_integration/vm1_load_transient_string_integration.cpp)
target_link_libraries(vm1_load_transient_string_integration PRIVATE vmp_runtime_vm1 vmp_runtime_strings vmp_runtime_audit)
set_target_properties(vm1_load_transient_string_integration PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_test(NAME vm1_load_transient_string_integration COMMAND $<TARGET_FILE:vm1_load_transient_string_integration>)
set_tests_properties(vm1_load_transient_string_integration PROPERTIES PASS_REGULAR_EXPRESSION "vm1_load_transient_string_integration OK")

add_test(NAME vmp_string_protect_round_trip
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/strings/vmp_string_protect_roundtrip.py $<TARGET_FILE:vmp-string-protect> $<TARGET_FILE:vmp-vm1-asm> $<TARGET_FILE:vmp-vm1-run>)
set_tests_properties(vmp_string_protect_round_trip PROPERTIES PASS_REGULAR_EXPRESSION "vmp-string-protect round-trip OK")

add_test(NAME vmp_protect_strings
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/strings/vmp_protect_strings.py $<TARGET_FILE:vmp-protect>)
set_tests_properties(vmp_protect_strings PROPERTIES PASS_REGULAR_EXPRESSION "vmp-protect strings OK")

add_test(NAME vmp_vm1_run_fib20
  COMMAND $<TARGET_FILE:vmp-vm1-run> ${CMAKE_BINARY_DIR}/tests/fib20.vm1 20)
set_tests_properties(vmp_vm1_run_fib20 PROPERTIES
  DEPENDS vmp_vm1_asm_fib20
  PASS_REGULAR_EXPRESSION "ret_int=6765")

# runtime/vm2 tests
add_executable(vm2_asm_round_trip ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2/vm2_asm_round_trip.cpp)
target_link_libraries(vm2_asm_round_trip PRIVATE vmp_runtime_vm2 vmp_runtime_audit)
set_target_properties(vm2_asm_round_trip PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm2_arith_ops ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2/vm2_arith_ops.cpp)
target_link_libraries(vm2_arith_ops PRIVATE vmp_runtime_vm2 vmp_runtime_audit)
set_target_properties(vm2_arith_ops PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm2_control_flow ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2/vm2_control_flow.cpp)
target_link_libraries(vm2_control_flow PRIVATE vmp_runtime_vm2 vmp_runtime_audit)
set_target_properties(vm2_control_flow PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm2_calling_convention ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2/vm2_calling_convention.cpp)
target_link_libraries(vm2_calling_convention PRIVATE vmp_runtime_vm2 vmp_runtime_audit)
set_target_properties(vm2_calling_convention PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm2_cross_domain ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2/vm2_cross_domain.cpp)
target_link_libraries(vm2_cross_domain PRIVATE vmp_runtime_vm2 vmp_runtime_vm1 vmp_runtime_audit)
set_target_properties(vm2_cross_domain PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm2_exceptions ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2/vm2_exceptions.cpp)
target_link_libraries(vm2_exceptions PRIVATE vmp_runtime_vm2 vmp_runtime_audit)
set_target_properties(vm2_exceptions PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm2_breakpoint_event ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2/vm2_breakpoint_event.cpp)
target_link_libraries(vm2_breakpoint_event PRIVATE vmp_runtime_vm2 vmp_runtime_audit)
set_target_properties(vm2_breakpoint_event PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(vm2_string_integration ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2/vm2_string_integration.cpp)
target_link_libraries(vm2_string_integration PRIVATE vmp_runtime_vm2 vmp_runtime_strings vmp_runtime_audit)
set_target_properties(vm2_string_integration PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_executable(isa_isolation ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2/isa_isolation.cpp)
target_link_libraries(isa_isolation PRIVATE vmp_runtime_vm2 vmp_runtime_vm1 vmp_runtime_audit)
set_target_properties(isa_isolation PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

add_test(NAME vm2_asm_round_trip COMMAND $<TARGET_FILE:vm2_asm_round_trip>)
set_tests_properties(vm2_asm_round_trip PROPERTIES PASS_REGULAR_EXPRESSION "vm2_asm_round_trip OK")
add_test(NAME vm2_arith_ops COMMAND $<TARGET_FILE:vm2_arith_ops>)
set_tests_properties(vm2_arith_ops PROPERTIES PASS_REGULAR_EXPRESSION "vm2_arith_ops OK")
add_test(NAME vm2_control_flow COMMAND $<TARGET_FILE:vm2_control_flow>)
set_tests_properties(vm2_control_flow PROPERTIES PASS_REGULAR_EXPRESSION "vm2_control_flow OK")
add_test(NAME vm2_calling_convention COMMAND $<TARGET_FILE:vm2_calling_convention>)
set_tests_properties(vm2_calling_convention PROPERTIES PASS_REGULAR_EXPRESSION "vm2_calling_convention OK")
add_test(NAME vm2_cross_domain COMMAND $<TARGET_FILE:vm2_cross_domain>)
set_tests_properties(vm2_cross_domain PROPERTIES PASS_REGULAR_EXPRESSION "vm2_cross_domain OK")
add_test(NAME vm2_exceptions COMMAND $<TARGET_FILE:vm2_exceptions>)
set_tests_properties(vm2_exceptions PROPERTIES PASS_REGULAR_EXPRESSION "vm2_exceptions OK")
add_test(NAME vm2_breakpoint_event COMMAND $<TARGET_FILE:vm2_breakpoint_event>)
set_tests_properties(vm2_breakpoint_event PROPERTIES PASS_REGULAR_EXPRESSION "vm2_breakpoint_event OK")
add_test(NAME vm2_string_integration COMMAND $<TARGET_FILE:vm2_string_integration>)
set_tests_properties(vm2_string_integration PROPERTIES PASS_REGULAR_EXPRESSION "vm2_string_integration OK")
add_test(NAME isa_isolation COMMAND $<TARGET_FILE:isa_isolation>)
set_tests_properties(isa_isolation PROPERTIES PASS_REGULAR_EXPRESSION "isa_isolation OK")

add_test(NAME vmp_vm2_asm_fib20
  COMMAND $<TARGET_FILE:vmp-vm2-asm> ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2/fixtures/fib20.vm2s ${CMAKE_BINARY_DIR}/tests/fib20.vm2)
set_tests_properties(vmp_vm2_asm_fib20 PROPERTIES PASS_REGULAR_EXPRESSION "assembled")

add_test(NAME vmp_vm2_run_fib20
  COMMAND $<TARGET_FILE:vmp-vm2-run> ${CMAKE_BINARY_DIR}/tests/fib20.vm2 20)
set_tests_properties(vmp_vm2_run_fib20 PROPERTIES
  DEPENDS vmp_vm2_asm_fib20
  PASS_REGULAR_EXPRESSION "ret_int=6765")


# loader tests
if(UNIX AND NOT APPLE)
  set(VMP_LOADER_TEST_LOG ${CMAKE_BINARY_DIR}/tests/vmp_loader_selftest.log)
  set(VMP_LOADER_ENV_LOG /tmp/vmp_loader_test.log)
  set(VMP_LOADER_DISABLE_LOG ${CMAKE_BINARY_DIR}/tests/vmp_loader_disabled.log)
  set(VMP_LOADER_PRELOAD_LOG ${CMAKE_BINARY_DIR}/tests/vmp_loader_preload.log)

  add_executable(loader_linux_init_order ${CMAKE_CURRENT_SOURCE_DIR}/loader/loader_linux_init_order.cpp)
  target_link_libraries(loader_linux_init_order PRIVATE vmp_loader_linux vmp_runtime_state)
  set_target_properties(loader_linux_init_order PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
  add_test(NAME loader_linux_init_order COMMAND $<TARGET_FILE:loader_linux_init_order>)
  set_tests_properties(loader_linux_init_order PROPERTIES PASS_REGULAR_EXPRESSION "loader_init_order OK")

  add_executable(loader_preload_probe ${CMAKE_CURRENT_SOURCE_DIR}/loader/loader_preload_probe.cpp)
  set_target_properties(loader_preload_probe PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

  add_test(NAME loader_selftest_audit_init
    COMMAND ${CMAKE_COMMAND} -E env VMP_AUDIT_PATH=${VMP_LOADER_TEST_LOG} $<TARGET_FILE:vmp-loader-selftest>)
  add_test(NAME loader_selftest_audit_init_check
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/loader/assert_audit_log.py ${VMP_LOADER_TEST_LOG} loader_init)
  set_tests_properties(loader_selftest_audit_init_check PROPERTIES DEPENDS loader_selftest_audit_init PASS_REGULAR_EXPRESSION "audit log OK")

  add_test(NAME loader_env_override_path
    COMMAND ${CMAKE_COMMAND} -E env VMP_AUDIT_PATH=${VMP_LOADER_ENV_LOG} $<TARGET_FILE:vmp-loader-selftest>)
  add_test(NAME loader_env_override_path_check
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/loader/assert_audit_log.py ${VMP_LOADER_ENV_LOG} loader_init)
  set_tests_properties(loader_env_override_path_check PROPERTIES DEPENDS loader_env_override_path PASS_REGULAR_EXPRESSION "audit log OK")

  add_test(NAME loader_disable
    COMMAND ${CMAKE_COMMAND} -E env VMP_DISABLE_LOADER=1 VMP_AUDIT_PATH=${VMP_LOADER_DISABLE_LOG} $<TARGET_FILE:vmp-loader-selftest>)
  add_test(NAME loader_disable_check
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/loader/assert_log_absent.py ${VMP_LOADER_DISABLE_LOG})
  set_tests_properties(loader_disable_check PROPERTIES DEPENDS loader_disable PASS_REGULAR_EXPRESSION "log absent OK")

  add_test(NAME loader_linux_shared_lib_preload
    COMMAND ${CMAKE_COMMAND} -E env LD_PRELOAD=$<TARGET_FILE:vmp_loader_linux> VMP_AUDIT_PATH=${VMP_LOADER_PRELOAD_LOG} $<TARGET_FILE:loader_preload_probe>)
  add_test(NAME loader_linux_shared_lib_preload_check
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/loader/assert_audit_log.py ${VMP_LOADER_PRELOAD_LOG} loader_init)
  set_tests_properties(loader_linux_shared_lib_preload_check PROPERTIES DEPENDS loader_linux_shared_lib_preload PASS_REGULAR_EXPRESSION "audit log OK")
  add_executable(loader_capability_gate_disallow ${CMAKE_CURRENT_SOURCE_DIR}/loader/loader_capability_gate_disallow.cpp)
  target_link_libraries(loader_capability_gate_disallow PRIVATE vmp_loader_linux vmp_runtime_vm1 vmp_runtime_state vmp_runtime_audit vmp_runtime_strings)
  target_compile_definitions(loader_capability_gate_disallow PRIVATE VMP_LOADER_SELFTEST_PATH="$<TARGET_FILE:vmp-loader-selftest>")
  set_target_properties(loader_capability_gate_disallow PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
  add_test(NAME loader_capability_gate_disallow COMMAND $<TARGET_FILE:loader_capability_gate_disallow>)
  set_tests_properties(loader_capability_gate_disallow PROPERTIES PASS_REGULAR_EXPRESSION "loader_capability_gate_disallow OK")

  find_package(JNI QUIET)
  if(JNI_FOUND)
    add_library(loader_android_jni_onload_probe SHARED ${CMAKE_CURRENT_SOURCE_DIR}/loader/loader_android_jni_onload_link_probe.cpp)
    target_include_directories(loader_android_jni_onload_probe PRIVATE ${JNI_INCLUDE_DIRS})
    target_link_libraries(loader_android_jni_onload_probe PRIVATE vmp_loader_android)
    set_target_properties(loader_android_jni_onload_probe PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests OUTPUT_NAME loader_android_jni_onload_probe)
    add_test(NAME loader_android_jni_onload_link_probe
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/loader/assert_nm_symbol.py ${CMAKE_NM} $<TARGET_FILE:loader_android_jni_onload_probe> JNI_OnLoad)
    set_tests_properties(loader_android_jni_onload_link_probe PROPERTIES PASS_REGULAR_EXPRESSION "nm symbol OK")
  endif()
endif()

if(WIN32)
  set(VMP_LOADER_TEST_LOG $ENV{TEMP}/vmp_loader_selftest.log)
  set(VMP_LOADER_ENV_LOG $ENV{TEMP}/vmp_loader_test.log)
  set(VMP_LOADER_DISABLE_LOG $ENV{TEMP}/vmp_loader_disabled.log)

  add_test(NAME loader_selftest_audit_init
    COMMAND ${CMAKE_COMMAND} -E env VMP_AUDIT_PATH=${VMP_LOADER_TEST_LOG} $<TARGET_FILE:vmp-loader-selftest>)
  add_test(NAME loader_selftest_audit_init_check
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/loader/assert_audit_log.py ${VMP_LOADER_TEST_LOG} loader_init)
  set_tests_properties(loader_selftest_audit_init_check PROPERTIES DEPENDS loader_selftest_audit_init PASS_REGULAR_EXPRESSION "audit log OK")

  add_test(NAME loader_env_override_path
    COMMAND ${CMAKE_COMMAND} -E env VMP_AUDIT_PATH=${VMP_LOADER_ENV_LOG} $<TARGET_FILE:vmp-loader-selftest>)
  add_test(NAME loader_env_override_path_check
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/loader/assert_audit_log.py ${VMP_LOADER_ENV_LOG} loader_init)
  set_tests_properties(loader_env_override_path_check PROPERTIES DEPENDS loader_env_override_path PASS_REGULAR_EXPRESSION "audit log OK")

  add_test(NAME loader_disable
    COMMAND ${CMAKE_COMMAND} -E env VMP_DISABLE_LOADER=1 VMP_AUDIT_PATH=${VMP_LOADER_DISABLE_LOG} $<TARGET_FILE:vmp-loader-selftest>)
  add_test(NAME loader_disable_check
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/loader/assert_log_absent.py ${VMP_LOADER_DISABLE_LOG})
  set_tests_properties(loader_disable_check PROPERTIES DEPENDS loader_disable PASS_REGULAR_EXPRESSION "log absent OK")

  add_test(NAME loader_windows_tls_callback_presence
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/loader/pe_tls_callback_check.py $<TARGET_FILE:vmp-loader-selftest>)
  set_tests_properties(loader_windows_tls_callback_presence PROPERTIES PASS_REGULAR_EXPRESSION "PE TLS callback section OK")
endif()


# runtime/vm1 JIT tests
function(vmp_add_vm1_jit_test target source)
  add_executable(${target} ${source})
  target_link_libraries(${target} PRIVATE vmp_runtime_vm1 vmp_runtime_strings vmp_runtime_audit vmp_runtime_state)
  set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
  if(UNIX AND NOT APPLE)
    target_link_options(${target} PRIVATE -Wl,--export-dynamic)
  elseif(APPLE)
    target_link_options(${target} PRIVATE -Wl,-export_dynamic)
  endif()
  add_test(NAME ${target} COMMAND $<TARGET_FILE:${target}>)
  set_tests_properties(${target} PROPERTIES PASS_REGULAR_EXPRESSION "${target} OK")
endfunction()

function(vmp_add_vm2_jit_test target source)
  add_executable(${target} ${source})
  target_link_libraries(${target} PRIVATE vmp_runtime_vm2 vmp_runtime_strings vmp_runtime_audit vmp_runtime_state)
  set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
  if(UNIX AND NOT APPLE)
    target_link_options(${target} PRIVATE -Wl,--export-dynamic)
  elseif(APPLE)
    target_link_options(${target} PRIVATE -Wl,-export_dynamic)
  endif()
  add_test(NAME ${target} COMMAND $<TARGET_FILE:${target}>)
  set_tests_properties(${target} PROPERTIES PASS_REGULAR_EXPRESSION "${target} OK")
endfunction()

vmp_add_vm1_jit_test(jit_correctness_add_loop ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1_jit/jit_correctness_add_loop.cpp)
vmp_add_vm1_jit_test(jit_correctness_fib_recursive ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1_jit/jit_correctness_fib_recursive.cpp)
vmp_add_vm1_jit_test(jit_string_barrier ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1_jit/jit_string_barrier.cpp)
vmp_add_vm1_jit_test(jit_domain_call_no_inlining ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1_jit/jit_domain_call_no_inlining.cpp)
vmp_add_vm1_jit_test(jit_invalidate_key_rotation ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1_jit/jit_invalidate_key_rotation.cpp)
vmp_add_vm1_jit_test(jit_cache_size_bound ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1_jit/jit_cache_size_bound.cpp)
vmp_add_vm1_jit_test(jit_backend_switch ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1_jit/jit_backend_switch.cpp)
vmp_add_vm1_jit_test(jit_disabled ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1_jit/jit_disabled.cpp)
vmp_add_vm1_jit_test(jit_no_degrade_to_native ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm1_jit/jit_no_degrade_to_native.cpp)

vmp_add_vm2_jit_test(vm2_jit_correctness_fib20 ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2_jit/vm2_jit_correctness_fib20.cpp)
vmp_add_vm2_jit_test(vm2_jit_function_level_only ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2_jit/vm2_jit_function_level_only.cpp)
vmp_add_vm2_jit_test(vm2_jit_integrity_failure_evicts ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2_jit/vm2_jit_integrity_failure_evicts.cpp)
vmp_add_vm2_jit_test(vm2_jit_predicate_preserved ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2_jit/vm2_jit_predicate_preserved.cpp)
vmp_add_vm2_jit_test(vm2_jit_tsload_no_speculation ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2_jit/vm2_jit_tsload_no_speculation.cpp)
vmp_add_vm2_jit_test(vm2_jit_invalidate_key_rotation ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2_jit/vm2_jit_invalidate_key_rotation.cpp)
vmp_add_vm2_jit_test(vm2_jit_invalidate_integrity ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2_jit/vm2_jit_invalidate_integrity.cpp)
vmp_add_vm2_jit_test(vm2_jit_backend_parity ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2_jit/vm2_jit_backend_parity.cpp)
vmp_add_vm2_jit_test(vm2_jit_disabled ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2_jit/vm2_jit_disabled.cpp)
vmp_add_vm2_jit_test(vm2_jit_no_degrade_to_native ${CMAKE_CURRENT_SOURCE_DIR}/runtime_vm2_jit/vm2_jit_no_degrade_to_native.cpp)

set(VMP_VM1_EXECUTABLE_TARGETS
  vm1_asm_round_trip
  vm1_arith_ops
  vm1_control_flow
  vm1_call_ret
  vm1_cross_domain_call
  vm1_exceptions
  vm1_breakpoint_event
  vm1_bench
  vm1_load_transient_string_integration
  jit_correctness_add_loop
  jit_correctness_fib_recursive
  jit_string_barrier
  jit_domain_call_no_inlining
  jit_invalidate_key_rotation
  jit_cache_size_bound
  jit_backend_switch
  jit_disabled
  jit_no_degrade_to_native
  vm2_jit_correctness_fib20
  vm2_jit_function_level_only
  vm2_jit_integrity_failure_evicts
  vm2_jit_predicate_preserved
  vm2_jit_tsload_no_speculation
  vm2_jit_invalidate_key_rotation
  vm2_jit_invalidate_integrity
  vm2_jit_backend_parity
  vm2_jit_disabled
  vm2_jit_no_degrade_to_native)
foreach(target IN LISTS VMP_VM1_EXECUTABLE_TARGETS)
  if(TARGET ${target})
    if(UNIX AND NOT APPLE)
      target_link_options(${target} PRIVATE -Wl,--export-dynamic)
    elseif(APPLE)
      target_link_options(${target} PRIVATE -Wl,-export_dynamic)
    endif()
  endif()
endforeach()

# backends/rewriter tests
add_test(NAME rewriter_elf_roundtrip
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/backends_rewriter/rewriter_elf_roundtrip.py $<TARGET_FILE:vmp-protect> ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})
set_tests_properties(rewriter_elf_roundtrip PROPERTIES PASS_REGULAR_EXPRESSION "rewriter_elf_roundtrip OK")

add_test(NAME rewriter_pe_roundtrip
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/backends_rewriter/rewriter_pe_roundtrip.py $<TARGET_FILE:vmp-protect> ${CMAKE_BINARY_DIR})
set_tests_properties(rewriter_pe_roundtrip PROPERTIES PASS_REGULAR_EXPRESSION "rewriter_pe_roundtrip OK" SKIP_REGULAR_EXPRESSION "SKIP_REASON")

add_test(NAME rewriter_macho_roundtrip
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/backends_rewriter/rewriter_macho_roundtrip.py $<TARGET_FILE:vmp-protect> ${CMAKE_BINARY_DIR})
set_tests_properties(rewriter_macho_roundtrip PROPERTIES PASS_REGULAR_EXPRESSION "rewriter_macho_roundtrip OK")

add_test(NAME rewriter_apk_passthrough
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/backends_rewriter/rewriter_apk_passthrough.py $<TARGET_FILE:vmp-protect> ${CMAKE_BINARY_DIR})
set_tests_properties(rewriter_apk_passthrough PROPERTIES PASS_REGULAR_EXPRESSION "rewriter_apk_passthrough OK")

add_test(NAME rewriter_ipa_passthrough
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/backends_rewriter/rewriter_ipa_passthrough.py $<TARGET_FILE:vmp-protect> ${CMAKE_BINARY_DIR})
set_tests_properties(rewriter_ipa_passthrough PROPERTIES PASS_REGULAR_EXPRESSION "rewriter_ipa_passthrough OK")

add_test(NAME rewriter_unknown_format_rejected
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/backends_rewriter/rewriter_unknown_format_rejected.py $<TARGET_FILE:vmp-protect> ${CMAKE_BINARY_DIR})
set_tests_properties(rewriter_unknown_format_rejected PROPERTIES PASS_REGULAR_EXPRESSION "rewriter_unknown_format_rejected OK")

add_test(NAME rewriter_policy_mismatch
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/backends_rewriter/rewriter_policy_mismatch.py $<TARGET_FILE:vmp-protect> ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR})
set_tests_properties(rewriter_policy_mismatch PROPERTIES PASS_REGULAR_EXPRESSION "rewriter_policy_mismatch OK")

# arch lifting tests
add_executable(x86_lift_basic ${CMAKE_CURRENT_SOURCE_DIR}/arch/x86_lift_basic.cpp)
target_link_libraries(x86_lift_basic PRIVATE vmp_arch_x86 vmp_runtime_vm1)
set_target_properties(x86_lift_basic PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME x86_lift_basic COMMAND $<TARGET_FILE:x86_lift_basic>)
set_tests_properties(x86_lift_basic PROPERTIES PASS_REGULAR_EXPRESSION "x86_lift_basic OK")

add_executable(x64_lift_basic_sysv ${CMAKE_CURRENT_SOURCE_DIR}/arch/x64_lift_basic_sysv.cpp)
target_link_libraries(x64_lift_basic_sysv PRIVATE vmp_arch_x64 vmp_runtime_vm1 vmp_runtime_vm2)
set_target_properties(x64_lift_basic_sysv PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME x64_lift_basic_sysv COMMAND $<TARGET_FILE:x64_lift_basic_sysv>)
set_tests_properties(x64_lift_basic_sysv PROPERTIES PASS_REGULAR_EXPRESSION "x64_lift_basic_sysv OK")

add_executable(x64_lift_basic_msvc ${CMAKE_CURRENT_SOURCE_DIR}/arch/x64_lift_basic_msvc.cpp)
target_link_libraries(x64_lift_basic_msvc PRIVATE vmp_arch_x64 vmp_runtime_vm1 vmp_runtime_vm2)
set_target_properties(x64_lift_basic_msvc PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME x64_lift_basic_msvc COMMAND $<TARGET_FILE:x64_lift_basic_msvc>)
set_tests_properties(x64_lift_basic_msvc PROPERTIES PASS_REGULAR_EXPRESSION "x64_lift_basic_msvc OK")

add_executable(arm_lift_basic ${CMAKE_CURRENT_SOURCE_DIR}/arch/arm_lift_basic.cpp)
target_link_libraries(arm_lift_basic PRIVATE vmp_arch_arm vmp_runtime_vm1)
set_target_properties(arm_lift_basic PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME arm_lift_basic COMMAND $<TARGET_FILE:arm_lift_basic>)
set_tests_properties(arm_lift_basic PROPERTIES PASS_REGULAR_EXPRESSION "arm_lift_basic OK")

add_executable(arm64_lift_basic ${CMAKE_CURRENT_SOURCE_DIR}/arch/arm64_lift_basic.cpp)
target_link_libraries(arm64_lift_basic PRIVATE vmp_arch_arm64 vmp_runtime_vm1)
set_target_properties(arm64_lift_basic PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME arm64_lift_basic COMMAND $<TARGET_FILE:arm64_lift_basic>)
set_tests_properties(arm64_lift_basic PROPERTIES PASS_REGULAR_EXPRESSION "arm64_lift_basic OK")

add_executable(lift_unsupported_diagnostic ${CMAKE_CURRENT_SOURCE_DIR}/arch/lift_unsupported_diagnostic.cpp)
target_link_libraries(lift_unsupported_diagnostic PRIVATE vmp_arch_x64 vmp_runtime_vm1 vmp_runtime_vm2)
set_target_properties(lift_unsupported_diagnostic PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME lift_unsupported_diagnostic COMMAND $<TARGET_FILE:lift_unsupported_diagnostic>)
set_tests_properties(lift_unsupported_diagnostic PROPERTIES PASS_REGULAR_EXPRESSION "lift_unsupported_diagnostic OK")

add_executable(lift_relocation_carrying ${CMAKE_CURRENT_SOURCE_DIR}/arch/lift_relocation_carrying.cpp)
target_link_libraries(lift_relocation_carrying PRIVATE vmp_arch_x64 vmp_runtime_vm1 vmp_runtime_vm2)
set_target_properties(lift_relocation_carrying PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
add_test(NAME lift_relocation_carrying COMMAND $<TARGET_FILE:lift_relocation_carrying>)
set_tests_properties(lift_relocation_carrying PROPERTIES PASS_REGULAR_EXPRESSION "lift_relocation_carrying OK")

add_test(NAME rewriter_lift_integration_elf
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/arch/rewriter_lift_integration_elf.py $<TARGET_FILE:vmp-protect> ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})
set_tests_properties(rewriter_lift_integration_elf PROPERTIES PASS_REGULAR_EXPRESSION "rewriter_lift_integration_elf OK")
