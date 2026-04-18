vmp_add_placeholder_library(vmp_loader_ios
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/loader/ios/ios_loader.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/ios_loader.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_loader_ios PUBLIC vmp_runtime_state vmp_runtime_audit)
