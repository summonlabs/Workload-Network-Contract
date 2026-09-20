# Test targets. Every suite is an independent executable so that a crash or a
# hang in one surface cannot mask another, and so that CTest reports each
# surface separately.

add_library(wnc_test_harness STATIC harness/wnc_test_main.cpp)
target_include_directories(wnc_test_harness PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/harness")
target_link_libraries(wnc_test_harness PUBLIC wnc)
wnc_apply_build_options(wnc_test_harness)

function(wnc_add_test_suite name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE wnc_test_harness)
  wnc_apply_build_options(${name})
  add_test(NAME ${name} COMMAND ${name})
  # No timeout: a hanging suite is a defect to diagnose, not to cut short.
  set_tests_properties(${name} PROPERTIES TIMEOUT 0)
endfunction()

# The multiprocess suites spawn this executable as real child processes, so it
# is built next to the test binaries and never installed.
add_executable(wnc_test_tool support/wnc_test_tool.cpp)
target_link_libraries(wnc_test_tool PRIVATE wnc)
wnc_apply_build_options(wnc_test_tool)

set(WNC_TEST_SOURCES
  "unit/test_core.cpp"
  "unit/test_json.cpp"
  "unit/test_crypto.cpp"
  "unit/test_contract.cpp"
  "unit/test_policy.cpp"
  "unit/test_evaluation.cpp"
  "unit/test_runtime.cpp"
  "property/test_property.cpp"
  "adversarial/test_adversarial.cpp"
  "persistence/test_persistence.cpp"
  "concurrency/test_concurrency.cpp"
  "protocol/test_protocol.cpp"
  "integration/test_integration.cpp"
  "multiprocess/test_multiprocess.cpp")

foreach(source IN LISTS WNC_TEST_SOURCES)
  get_filename_component(stem "${source}" NAME_WE)
  wnc_add_test_suite(wnc_${stem} "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
endforeach()
