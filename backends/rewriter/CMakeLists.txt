add_library(vmp_backend_rewriter STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/rewriter_backend.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/formats/elf.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/formats/pe.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/formats/macho.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/formats/zip.cpp)

target_include_directories(vmp_backend_rewriter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vmp_backend_rewriter PUBLIC vmp_planner vmp_policy vmp_runtime_strings nlohmann_json::nlohmann_json)
