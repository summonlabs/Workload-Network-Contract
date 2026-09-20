# Coordinator service executable.
add_executable(wnc-coordinator coordinator_main.cpp)
target_link_libraries(wnc-coordinator PRIVATE wnc)
wnc_apply_build_options(wnc-coordinator)
install(TARGETS wnc-coordinator RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
