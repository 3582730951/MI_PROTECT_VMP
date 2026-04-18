vmp_add_placeholder_library(vmp_arch_arm
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/arch/arm/arm.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/arm.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_arch_arm PUBLIC vmp_policy)
