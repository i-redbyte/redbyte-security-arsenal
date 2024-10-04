#include "hash_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void test_hash_table_create() {
    HashTable *table = hash_table_create();
    assert(table != NULL);
    printf("test_hash_table_create passed.\n");
    hash_table_destroy(table, NULL);
}

void test_hash_table_insert_and_get() {
    HashTable *table = hash_table_create();
    assert(table != NULL);

    const char *key = "test_key";
    const char *value = "test_value";

    bool inserted = hash_table_insert(table, key, (void *)value);
    assert(inserted);

    char *retrieved_value = (char *)hash_table_get(table, key);
    assert(retrieved_value != NULL);
    assert(strcmp(retrieved_value, value) == 0);

    printf("test_hash_table_insert_and_get passed.\n");
    hash_table_destroy(table, NULL);
}

void test_hash_table_update() {
    HashTable *table = hash_table_create();
    assert(table != NULL);

    const char *key = "test_key";
    const char *value1 = "value1";
    const char *value2 = "value2";

    hash_table_insert(table, key, (void *)value1);
    hash_table_insert(table, key, (void *)value2);

    char *retrieved_value = (char *)hash_table_get(table, key);
    assert(retrieved_value != NULL);
    assert(strcmp(retrieved_value, value2) == 0);

    printf("test_hash_table_update passed.\n");
    hash_table_destroy(table, NULL);
}

void test_hash_table_contains() {
    HashTable *table = hash_table_create();
    assert(table != NULL);

    const char *key = "test_key";
    const char *value = "test_value";

    hash_table_insert(table, key, (void *)value);

    assert(hash_table_contains(table, key));
    assert(!hash_table_contains(table, "non_existent_key"));

    printf("test_hash_table_contains passed.\n");
    hash_table_destroy(table, NULL);
}

void test_hash_table_resize() {
    HashTable *table = hash_table_create();
    assert(table != NULL);

    for (int i = 0; i < 1000; i++) {
        char key[20];
        sprintf(key, "key_%d", i);
        char *value = malloc(20);
        sprintf(value, "value_%d", i);
        bool inserted = hash_table_insert(table, key, value);
        assert(inserted);
    }

    for (int i = 0; i < 1000; i++) {
        char key[20];
        sprintf(key, "key_%d", i);
        char *retrieved_value = (char *)hash_table_get(table, key);
        assert(retrieved_value != NULL);
    }

    printf("test_hash_table_resize passed.\n");
    hash_table_destroy(table, free);
}

int main() {
    test_hash_table_create();
    test_hash_table_insert_and_get();
    test_hash_table_update();
    test_hash_table_contains();
    test_hash_table_resize();

    printf("All tests passed.\n");
    return 0;
}
