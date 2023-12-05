cmake_minimum_required(VERSION 3.4)

project(llvm_mode VERSION 1.3.0 LANGUAGES C CXX)

include_directories(include)

##### Check LLVM
find_package(LLVM REQUIRED CONFIG)

if (LLVM_FOUND)
    message(STATUS "LLVM_VERSION_MAJOR: ${LLVM_VERSION_MAJOR}")
    message(STATUS "LLVM_VERSION_MINOR: ${LLVM_VERSION_MINOR}")
    if (NOT (${LLVM_VERSION_MAJOR} GREATER 9))
	message(STATUS ${CMAKE_VERSION})
        message(FATAL_ERROR "LLVM version must be at least 10!")
    endif()
else()
    message(FATAL_ERROR "You haven't install LLVM !")
endif()

add_compile_definitions(LLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR})

##### Compiler
add_executable(HopperClang hopper-clang.c)
set_target_properties(HopperClang PROPERTIES OUTPUT_NAME "hopper-clang")

add_custom_command(TARGET HopperClang POST_BUILD
    COMMAND ln -sf "hopper-clang" "hopper-clang++")
if (HOPPER_BIN_DIR)
    install (TARGETS HopperClang DESTINATION ${HOPPER_BIN_DIR})
    install (FILES ${CMAKE_CURRENT_BINARY_DIR}/hopper-clang++ DESTINATION ${HOPPER_BIN_DIR})
endif()

## LLVM Pass 

if (NOT TARGET LLVMPassConfig)
    add_library(LLVMPassConfig INTERFACE IMPORTED)
    set_target_properties(LLVMPassConfig PROPERTIES
        INTERFACE_COMPILE_OPTIONS "-fno-rtti" #-fpic
        INTERFACE_INCLUDE_DIRECTORIES "${LLVM_INCLUDE_DIRS}"
        INTERFACE_LINK_DIRECTORIES "${LLVM_LIBRARY_DIRS}"
        # INTERFACE_LINK_OPTIONS "-Wl,-znodelete"
    )
endif()

set (CMAKE_CXX_STANDARD 14)
if(APPLE)
    # User teor2345 reports that this is required to make things work on MacOS X.
    set (CMAKE_MODULE_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -Wl,-flat_namespace -Wl,-undefined,suppress")
else()
    # fix pass bug: https://github.com/sampsyo/llvm-pass-skeleton/issues/7#issuecomment-401834287
    set (CMAKE_MODULE_LINKER_FLAGS "${CMAKE_CXX_LINK_FLAGS} -Wl,-znodelete")
endif()

# add_library(HopperPrePass MODULE hopper-pre-pass.cc)
# target_link_libraries(HopperPrePass LLVMPassConfig)
# if (HOPPER_BIN_DIR)
#    install (TARGETS HopperPrePass DESTINATION ${HOPPER_BIN_DIR})
# endif()

add_library(HopperPass MODULE hopper-pass.cc)
target_link_libraries(HopperPass LLVMPassConfig)
if (HOPPER_BIN_DIR)
    install (TARGETS HopperPass DESTINATION ${HOPPER_BIN_DIR})
endif()