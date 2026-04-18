vmp_add_placeholder_library(vmp_arch_x86
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/arch/x86/x86.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/x86.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_arch_x86 PUBLIC vmp_policy vmp_arch_common vmp_runtime_vm1)
