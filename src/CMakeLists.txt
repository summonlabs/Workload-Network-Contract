add_library(wnc_objects OBJECT
  codec.cpp
  composition.cpp
  contract.cpp
  coordinator.cpp
  ed25519.cpp
  evaluation.cpp
  hash.cpp
  hash512.cpp
  identity.cpp
  json.cpp
  ledger.cpp
  policy.cpp
  runtime.cpp
  signature.cpp
  state.cpp
  wire.cpp)

target_include_directories(wnc_objects PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/../include>"
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_compile_definitions(wnc_objects PRIVATE WNC_BUILDING_LIBRARY=1)
set_target_properties(wnc_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(WNC_BUILD_SHARED)
  set(_wnc_libtype SHARED)
else()
  set(_wnc_libtype STATIC)
endif()

add_library(wnc ${_wnc_libtype} $<TARGET_OBJECTS:wnc_objects>)
add_library(WorkloadNetworkContract::wnc ALIAS wnc)
set_target_properties(wnc PROPERTIES
  OUTPUT_NAME wnc
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON)

target_include_directories(wnc PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/../include>"
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

wnc_apply_build_options(wnc)
wnc_apply_build_options(wnc_objects)

find_package(Threads REQUIRED)
target_link_libraries(wnc PUBLIC Threads::Threads)

if(WIN32)
  target_link_libraries(wnc PUBLIC ws2_32)
endif()

install(TARGETS wnc EXPORT workload-network-contract-targets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../include/wnc"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
# The generated version header is part of the installed interface.
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/../include/wnc/version.hpp"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wnc)
