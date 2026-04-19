add_library(vmp_arch_common STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/lifting.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/label_resolver.cpp)
target_link_libraries(vmp_arch_common PUBLIC vmp_build_options)
target_include_directories(vmp_arch_common PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/runtime/vm1/include
  ${CMAKE_SOURCE_DIR}/runtime/vm2/include
  ${CMAKE_SOURCE_DIR}/runtime/audit/include
  ${CMAKE_SOURCE_DIR}/runtime/bridge/include
  ${CMAKE_SOURCE_DIR}/runtime/strings/include
  ${CMAKE_SOURCE_DIR}/policy/include)
