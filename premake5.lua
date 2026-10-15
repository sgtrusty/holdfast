-- premake5.lua — build configuration for holdfast
--
-- Replaces CMakeLists.txt. Invoked by the `build` stage in predep.toml
-- (which runs `premake5 gmake && make config=<cfg>`), and can also be used
-- directly:  premake5 gmake && make config=release -j$(nproc)
--
-- The output layout mirrors the previous CMake build:
--   bin/holdfast        — the main executable
--   bin/holdfast_tests  — the unit-test binary (drives `predep test`)
--   bin/holdfast_core.a — static library shared by both
--
-- Hardening flags match the old CMake target exactly:
--   -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
--   -fstack-protector-strong ; -D_FORTIFY_SOURCE=2 in release ;
--   -Wl,-z,relro,-z,now on the executables ; pthread.
-- "Zero warnings is the bar": -Werror is ON by default. Disable with
--   HOLDFAST_WERROR=OFF predep        (or: premake5 gmake --no-werror)

workspace("holdfast")
  configurations({ "release", "debug" })

newoption {
  trigger = "no-werror",
  description = "Do not treat warnings as errors (override the project default of -Werror)",
}

-- The project's bar is "zero warnings". -Werror is ON unless explicitly off.
local werror = true
local env = os.getenv("HOLDFAST_WERROR")
if env == "OFF" or env == "0" or env == "off" then
  werror = false
end
if _OPTIONS["no-werror"] then
  werror = false
end

-- Shared, project-wide compiler settings (mirrors CMake target_compile_options
-- on holdfast_core, which were PUBLIC).
local WARN = {
  "-Wall", "-Wextra", "-Wpedantic", "-Wshadow", "-Wconversion",
  "-Wno-sign-conversion", "-fstack-protector-strong",
}

-- Mirrors the old CMake compile definitions (HOLDFAST_VERSION +
-- HOLDFAST_SHARE_DIR). SHARE_DIR follows the previous install prefix
-- (/usr/local/share/holdfast).
local SHARED_DEFINES = {
  'HOLDFAST_VERSION="0.1.0"',
  'HOLDFAST_SHARE_DIR="/usr/local/share/holdfast"',
}

-- Static core library: every translation unit under src/ except the executable
-- entry point (main.cpp), compiled once and linked by both the binary and the
-- unit tests.
project("holdfast_core")
  kind("StaticLib")
  language("C++")
  cppdialect("C++20")     -- -std=c++20 (no GNU extensions; was CMAKE_CXX_EXTENSIONS OFF)
  staticruntime("Off")
  targetdir("bin")
  includedirs({ "src" })
  files({ "src/**.cpp" })
  removefiles({ "src/main.cpp" })
  links({ "pthread" })
  buildoptions(WARN)
  defines(SHARED_DEFINES)
  filter("configurations:release")
    optimize("Speed")
    defines({ "NDEBUG", "_FORTIFY_SOURCE=2" })
  filter("configurations:debug")
    optimize("Debug")
    symbols("On")
  filter({})              -- back to "all configs" for the -Werror toggle
  if werror then
    buildoptions({ "-Werror" })
  end

-- Common settings for the two executables (main binary + unit tests).
local function executable(name, srcs, with_relro)
  project(name)
    kind("ConsoleApp")
    language("C++")
    cppdialect("C++20")
    staticruntime("Off")
    targetdir("bin")
    includedirs({ "src" })
    files(srcs)
    links({ "holdfast_core", "pthread" })
    buildoptions(WARN)
    defines(SHARED_DEFINES)
    if with_relro then
      linkoptions({ "-Wl,-z,relro,-z,now" })
    end
    filter("configurations:release")
      optimize("Speed")
      defines({ "NDEBUG", "_FORTIFY_SOURCE=2" })
    filter("configurations:debug")
      optimize("Debug")
      symbols("On")
    filter({})
    if werror then
      buildoptions({ "-Werror" })
    end
end

executable("holdfast", { "src/main.cpp" }, true)
executable("holdfast_tests", { "tests/test_main.cpp" }, false)
