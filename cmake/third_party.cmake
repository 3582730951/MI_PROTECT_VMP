include(FetchContent)

function(vmp_require_nlohmann_json)
  if(TARGET nlohmann_json::nlohmann_json)
    return()
  endif()

  find_package(nlohmann_json CONFIG QUIET)
  if(TARGET nlohmann_json::nlohmann_json)
    return()
  endif()

  message(STATUS "nlohmann_json not found via find_package; fetching v3.11.3")
  FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE
  )
  FetchContent_MakeAvailable(nlohmann_json)
endfunction()
