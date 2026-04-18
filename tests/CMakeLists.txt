configure_file(${CMAKE_CURRENT_SOURCE_DIR}/dummy_test.py ${CMAKE_CURRENT_BINARY_DIR}/dummy_test.py COPYONLY)

add_test(NAME dummy_python_smoke
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/dummy_test.py)

add_test(NAME dummy_vmp_protect_not_implemented
  COMMAND ${CMAKE_BINARY_DIR}/tools/vmp-protect)
set_tests_properties(dummy_vmp_protect_not_implemented PROPERTIES PASS_REGULAR_EXPRESSION "NOT_IMPLEMENTED")

add_test(NAME dummy_vmp_clang_not_implemented
  COMMAND ${CMAKE_BINARY_DIR}/tools/vmp-clang)
set_tests_properties(dummy_vmp_clang_not_implemented PROPERTIES PASS_REGULAR_EXPRESSION "NOT_IMPLEMENTED")
