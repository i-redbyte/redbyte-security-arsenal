enable_testing()

add_executable(test_hash_table test_hash_table.c)

target_link_libraries(test_hash_table hash_table)

add_test(NAME test_hash_table COMMAND test_hash_table)
