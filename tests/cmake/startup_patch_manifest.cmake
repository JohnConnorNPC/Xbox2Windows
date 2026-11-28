# Stage 2 memory patches (#3037; docs/experiments/patch-manifests.md): tools/startup/debug_launch.py writes a
# manifest's patches into a source-built probe before the probe's TLS callback runs, reports them in the
# summary, and exits 3 for a wrong expect_sha256 or input hash or a test fault; launch.py refuses manifests.
if(EXISTS "${INTAKE_PYTHON}")
    # The planner (tools/startup/patch_plan.py) on synthetic inputs; pure Python, also in the Linux job.
    add_test(NAME patch_plan_controls COMMAND "${INTAKE_PYTHON}" -B "${CMAKE_SOURCE_DIR}/tests/patch_plan_check.py")
    add_executable(startup_patch_probe tests/startup_patch_probe.cpp)
    target_compile_features(startup_patch_probe PRIVATE cxx_std_17)
    # The same probe with a preferred base on the shared user-data page, which is never free: the loader
    # must relocate it on Windows and under Wine.
    add_executable(startup_patch_probe_low tests/startup_patch_probe.cpp)
    target_compile_features(startup_patch_probe_low PRIVATE cxx_std_17)
    target_link_options(startup_patch_probe_low PRIVATE /BASE:0x7FFE0000 /DYNAMICBASE)
    add_test(NAME startup_patch_memory COMMAND "${INTAKE_PYTHON}" -B
        "${CMAKE_SOURCE_DIR}/tests/startup_patch_memory_check.py" "$<TARGET_FILE:startup_patch_probe>"
        "$<TARGET_FILE:startup_patch_probe_low>")
    set_tests_properties(startup_patch_memory PROPERTIES TIMEOUT 300)
endif()
