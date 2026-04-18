vmp_add_placeholder_library(vmp_arch_common
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/arch/common/lifting.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/lifting.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_arch_common PUBLIC vmp_runtime_vm1 vmp_runtime_vm2)
