#Project building


set(PROJECT_NAME netcracker)
project(${PROJECT_NAME})

file(GLOB_RECURSE SRC_FILES lib/*.cc)
add_executable(${PROJECT_NAME} main.cc ${SRC_FILES})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PUBLIC /usr/include/libnl3)

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -O2 -g )
target_link_libraries(${PROJECT_NAME} -lnl-3 -lnl-genl-3 -lgcrypt -pthread)

set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/${PROJECT_NAME})

#add_custom_command(
#  TARGET ${PROJECT_NAME} POST_BUILD
#  COMMAND ${PROJECT_NAME}
# WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin/
#  COMMENT "Runs program. ${CMAKE_BINARY_DIR}/bin/${PROJECT_NAME}"
#)
add_custom_command(
  TARGET ${PROJECT_NAME} POST_BUILD
  COMMAND cp ${CMAKE_BINARY_DIR}/../Passwords.txt ${CMAKE_BINARY_DIR}/bin/${PROJECT_NAME}
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin/
  COMMENT "Coping passwords list."
)
