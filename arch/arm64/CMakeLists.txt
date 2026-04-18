vmp_add_placeholder_library(vmp_arch_arm64
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/arch/arm64/arm64.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/arm64.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_arch_arm64 PUBLIC vmp_policy vmp_arch_common vmp_runtime_vm1)
