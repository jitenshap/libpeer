project(sample)

file(GLOB SRCS "*.c")

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(sample ${SRCS})

target_link_libraries(sample peer pthread)
