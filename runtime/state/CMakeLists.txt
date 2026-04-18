add_library(vmp_runtime_state STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/hot_recorder.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/profile.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/scheduler.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/state_machine.cpp)
target_link_libraries(vmp_runtime_state PUBLIC vmp_build_options vmp_runtime_audit vmp_runtime_strings nlohmann_json::nlohmann_json)
if(VMP_WITH_JIT)
  target_link_libraries(vmp_runtime_state PUBLIC vmp_runtime_jit)
  target_include_directories(vmp_runtime_state PUBLIC ${CMAKE_SOURCE_DIR}/runtime/jit/include)
  if(VMP_WITH_VM2)
    target_link_libraries(vmp_runtime_state PUBLIC vmp_runtime_vm2)
  endif()
endif()
target_link_libraries(vmp_runtime_state PUBLIC vmp_runtime_vm1)
target_include_directories(vmp_runtime_state PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
