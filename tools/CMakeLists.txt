# Coordinator service executable.
add_executable(wnc-coordinator coordinator_main.cpp)
target_link_libraries(wnc-coordinator PRIVATE wnc)
wnc_apply_build_options(wnc-coordinator)
install(TARGETS wnc-coordinator RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Inspection tool: validate, digest, explain, diff, compose, status, evaluate.
add_executable(wncctl wncctl_main.cpp)
target_link_libraries(wncctl PRIVATE wnc)
wnc_apply_build_options(wncctl)
install(TARGETS wncctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
