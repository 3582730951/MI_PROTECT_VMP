vmp_add_placeholder_library(vmp_loader_android
  HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/vmp/loader/android/android_loader.h
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/android_loader.cpp
  INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_loader_android PUBLIC vmp_runtime_state vmp_runtime_audit)
