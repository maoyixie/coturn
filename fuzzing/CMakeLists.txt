add_executable(FuzzStun FuzzStun.c)
target_link_libraries(FuzzStun turnclient ${LIB_FUZZING_ENGINE})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/input/FuzzStun_seed_corpus.zip
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

# add FuzzStun2
add_executable(FuzzStun2 FuzzStun2.c)
target_link_libraries(FuzzStun2 turnclient ${LIB_FUZZING_ENGINE})
# empty seed

# add FuzzStun3
add_executable(FuzzStun3 FuzzStun3.c)
target_link_libraries(FuzzStun3 turnclient ${LIB_FUZZING_ENGINE})
# empty seed

set(FuzzStunClientSRC
    ${CMAKE_CURRENT_SOURCE_DIR}/FuzzStunClient.c
    ${PROJECT_SOURCE_DIR}/src/apps/common/stun_buffer.c
)

add_executable(FuzzStunClient ${FuzzStunClientSRC})
target_link_libraries(FuzzStunClient turnclient ${LIB_FUZZING_ENGINE})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/input/FuzzStunClient_seed_corpus.zip
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
