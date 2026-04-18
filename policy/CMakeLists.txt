vmp_add_placeholder_library(vmp_policy
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/policy/policy_ir.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/policy_ir.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(vmp_policy PUBLIC nlohmann_json::nlohmann_json)
