configure_file(${CMAKE_CURRENT_SOURCE_DIR}/dummy_test.py ${CMAKE_CURRENT_BINARY_DIR}/dummy_test.py COPYONLY)

add_executable(policy_cpp_test ${CMAKE_CURRENT_SOURCE_DIR}/policy/policy_cpp_test.cpp)
target_link_libraries(policy_cpp_test PRIVATE vmp_policy)

add_executable(policy_cpp_summary ${CMAKE_CURRENT_SOURCE_DIR}/policy/policy_cpp_summary.cpp)
target_link_libraries(policy_cpp_summary PRIVATE vmp_policy)

add_test(NAME dummy_python_smoke
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/dummy_test.py)

add_test(NAME policy_cpp_test
  COMMAND policy_cpp_test)

add_test(NAME vmp_protect_good_policy
  COMMAND ${CMAKE_BINARY_DIR}/tools/vmp-protect --policy ${CMAKE_CURRENT_SOURCE_DIR}/policy/examples/good.json)
set_tests_properties(vmp_protect_good_policy PROPERTIES PASS_REGULAR_EXPRESSION "OK: policy loaded, 2 entries, schema=v1")

add_test(NAME vmp_protect_bad_policy
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/policy/assert_bad_policy.py ${CMAKE_BINARY_DIR}/tools/vmp-protect ${CMAKE_CURRENT_SOURCE_DIR}/policy/examples/bad_vm_func_native.json)
set_tests_properties(vmp_protect_bad_policy PROPERTIES PASS_REGULAR_EXPRESSION "bad policy rejected as expected")

add_test(NAME vmp_protect_dump_schema
  COMMAND ${CMAKE_BINARY_DIR}/tools/vmp-protect --dump-schema)
set_tests_properties(vmp_protect_dump_schema PROPERTIES PASS_REGULAR_EXPRESSION "language_origin")

add_test(NAME dummy_vmp_clang_not_implemented
  COMMAND ${CMAKE_BINARY_DIR}/tools/vmp-clang)
set_tests_properties(dummy_vmp_clang_not_implemented PROPERTIES PASS_REGULAR_EXPRESSION "NOT_IMPLEMENTED")
