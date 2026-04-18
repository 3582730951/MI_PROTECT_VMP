vmp_add_placeholder_tool(vmp-clang ${CMAKE_CURRENT_SOURCE_DIR}/src/vmp_clang.cpp)
vmp_add_placeholder_tool(vmp-clang++ ${CMAKE_CURRENT_SOURCE_DIR}/src/vmp_clangxx.cpp)
vmp_add_placeholder_tool(vmp-link ${CMAKE_CURRENT_SOURCE_DIR}/src/vmp_link.cpp)
vmp_add_placeholder_tool(vmp-protect ${CMAKE_CURRENT_SOURCE_DIR}/src/vmp_protect.cpp)

target_link_libraries(vmp-protect PRIVATE vmp_policy)
