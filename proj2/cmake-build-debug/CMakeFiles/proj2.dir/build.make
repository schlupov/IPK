# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/schlupov/school/CLion-2018.1.1/clion-2018.1.1/bin/cmake/bin/cmake

# The command to remove a file.
RM = /home/schlupov/school/CLion-2018.1.1/clion-2018.1.1/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/schlupov/school/ctvrty_semestr/IPK/proj2

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/schlupov/school/ctvrty_semestr/IPK/proj2/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/proj2.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/proj2.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/proj2.dir/flags.make

CMakeFiles/proj2.dir/ipk-scan.cpp.o: CMakeFiles/proj2.dir/flags.make
CMakeFiles/proj2.dir/ipk-scan.cpp.o: ../ipk-scan.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/schlupov/school/ctvrty_semestr/IPK/proj2/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/proj2.dir/ipk-scan.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/proj2.dir/ipk-scan.cpp.o -c /home/schlupov/school/ctvrty_semestr/IPK/proj2/ipk-scan.cpp

CMakeFiles/proj2.dir/ipk-scan.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/proj2.dir/ipk-scan.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/schlupov/school/ctvrty_semestr/IPK/proj2/ipk-scan.cpp > CMakeFiles/proj2.dir/ipk-scan.cpp.i

CMakeFiles/proj2.dir/ipk-scan.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/proj2.dir/ipk-scan.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/schlupov/school/ctvrty_semestr/IPK/proj2/ipk-scan.cpp -o CMakeFiles/proj2.dir/ipk-scan.cpp.s

CMakeFiles/proj2.dir/ipk-scan.cpp.o.requires:

.PHONY : CMakeFiles/proj2.dir/ipk-scan.cpp.o.requires

CMakeFiles/proj2.dir/ipk-scan.cpp.o.provides: CMakeFiles/proj2.dir/ipk-scan.cpp.o.requires
	$(MAKE) -f CMakeFiles/proj2.dir/build.make CMakeFiles/proj2.dir/ipk-scan.cpp.o.provides.build
.PHONY : CMakeFiles/proj2.dir/ipk-scan.cpp.o.provides

CMakeFiles/proj2.dir/ipk-scan.cpp.o.provides.build: CMakeFiles/proj2.dir/ipk-scan.cpp.o


CMakeFiles/proj2.dir/argument_parser.cpp.o: CMakeFiles/proj2.dir/flags.make
CMakeFiles/proj2.dir/argument_parser.cpp.o: ../argument_parser.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/schlupov/school/ctvrty_semestr/IPK/proj2/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/proj2.dir/argument_parser.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/proj2.dir/argument_parser.cpp.o -c /home/schlupov/school/ctvrty_semestr/IPK/proj2/argument_parser.cpp

CMakeFiles/proj2.dir/argument_parser.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/proj2.dir/argument_parser.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/schlupov/school/ctvrty_semestr/IPK/proj2/argument_parser.cpp > CMakeFiles/proj2.dir/argument_parser.cpp.i

CMakeFiles/proj2.dir/argument_parser.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/proj2.dir/argument_parser.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/schlupov/school/ctvrty_semestr/IPK/proj2/argument_parser.cpp -o CMakeFiles/proj2.dir/argument_parser.cpp.s

CMakeFiles/proj2.dir/argument_parser.cpp.o.requires:

.PHONY : CMakeFiles/proj2.dir/argument_parser.cpp.o.requires

CMakeFiles/proj2.dir/argument_parser.cpp.o.provides: CMakeFiles/proj2.dir/argument_parser.cpp.o.requires
	$(MAKE) -f CMakeFiles/proj2.dir/build.make CMakeFiles/proj2.dir/argument_parser.cpp.o.provides.build
.PHONY : CMakeFiles/proj2.dir/argument_parser.cpp.o.provides

CMakeFiles/proj2.dir/argument_parser.cpp.o.provides.build: CMakeFiles/proj2.dir/argument_parser.cpp.o


# Object files for target proj2
proj2_OBJECTS = \
"CMakeFiles/proj2.dir/ipk-scan.cpp.o" \
"CMakeFiles/proj2.dir/argument_parser.cpp.o"

# External object files for target proj2
proj2_EXTERNAL_OBJECTS =

proj2: CMakeFiles/proj2.dir/ipk-scan.cpp.o
proj2: CMakeFiles/proj2.dir/argument_parser.cpp.o
proj2: CMakeFiles/proj2.dir/build.make
proj2: CMakeFiles/proj2.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/schlupov/school/ctvrty_semestr/IPK/proj2/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable proj2"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/proj2.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/proj2.dir/build: proj2

.PHONY : CMakeFiles/proj2.dir/build

CMakeFiles/proj2.dir/requires: CMakeFiles/proj2.dir/ipk-scan.cpp.o.requires
CMakeFiles/proj2.dir/requires: CMakeFiles/proj2.dir/argument_parser.cpp.o.requires

.PHONY : CMakeFiles/proj2.dir/requires

CMakeFiles/proj2.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/proj2.dir/cmake_clean.cmake
.PHONY : CMakeFiles/proj2.dir/clean

CMakeFiles/proj2.dir/depend:
	cd /home/schlupov/school/ctvrty_semestr/IPK/proj2/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/schlupov/school/ctvrty_semestr/IPK/proj2 /home/schlupov/school/ctvrty_semestr/IPK/proj2 /home/schlupov/school/ctvrty_semestr/IPK/proj2/cmake-build-debug /home/schlupov/school/ctvrty_semestr/IPK/proj2/cmake-build-debug /home/schlupov/school/ctvrty_semestr/IPK/proj2/cmake-build-debug/CMakeFiles/proj2.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/proj2.dir/depend
