function(TARGET_USE_MODERN_CXX target)
  cmake_parse_arguments(PARSED "" "TYPE" "RELEASE_WHITELIST" ${ARGN})

  get_property(all_features GLOBAL PROPERTY CMAKE_CXX_KNOWN_FEATURES)
  if ("${PARSED_RELEASE_WHITELIST}" STREQUAL "")
    set(release_features ${all_features})
  else()
    set(release_features ${PARSED_RELEASE_WHITELIST})
  endif()

  if ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    target_compile_features("${target}" "${PARSED_TYPE}" ${release_features})
  else()
    target_compile_features("${target}" "${PARSED_TYPE}" ${all_features})
  endif()
endfunction()
