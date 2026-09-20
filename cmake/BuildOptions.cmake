# First-party warning, hardening, and sanitizer configuration.
#
# Every compile option is applied to first-party targets only, and every option
# is applied as a private usage requirement so that nothing leaks into the
# installed package: a downstream consumer must not inherit /W4 /WX or a
# sanitizer because it linked this library.
#
# Usage:  wnc_apply_build_options(<target>)

function(wnc_apply_build_options target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /EHsc /permissive- /Zc:__cplusplus /Zc:preprocessor /utf-8 /W4)
    if(WNC_STRICT_WARNINGS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(WNC_HARDENING)
      target_compile_options(${target} PRIVATE /GS /guard:cf)
    endif()
    if(WNC_SANITIZER)
      target_compile_options(${target} PRIVATE /fsanitize=address)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
      -Wold-style-cast -Wcast-qual -Wcast-align -Wnon-virtual-dtor -Woverloaded-virtual
      -Wdouble-promotion -Wformat=2 -Wundef -Wnull-dereference -Wimplicit-fallthrough)
    if(WNC_STRICT_WARNINGS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    if(WNC_HARDENING)
      target_compile_options(${target} PRIVATE -fstack-protector-strong)
      target_link_options(${target} PRIVATE -fstack-protector-strong)
    endif()
    if(WNC_SANITIZER)
      target_compile_options(${target} PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
      target_link_options(${target} PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    endif()
  endif()
endfunction()
