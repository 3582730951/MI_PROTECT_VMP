vmp_add_placeholder_library(vmp_arch_x64
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/arch/x64/x64.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/x64.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_arch_x64 PUBLIC vmp_policy vmp_arch_common vmp_runtime_vm1 vmp_runtime_vm2)
