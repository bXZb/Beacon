# Empty on purpose. ExternalProject for tools/llvm/pass must compile with
# the host toolchain (Linux g++) and must not inherit xwin/clang-cl.
# Official Windows LLVM builds report "Loadable modules not supported", so
# the pass plugin is a Linux host artifact; Windows CI smokes that DLL.
