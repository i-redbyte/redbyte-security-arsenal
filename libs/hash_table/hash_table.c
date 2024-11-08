#include "hash_table.h"
#include <stdlib.h>
#include <string.h>

#define INITIAL_TABLE_SIZE 256
#define LOAD_FACTOR_THRESHOLD 0.75

/**
 * Хеш-функция, использующая алгоритм djb2.
 */
static unsigned int hash(const char *key) {
    unsigned int hash = 5381;
    int c;
    while ((c = (unsigned char)*key++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

HashTable *hash_table_create(void) {
    HashTable *table = malloc(sizeof(HashTable));
    if (!table) {
        return NULL;
    }
    table->size = INITIAL_TABLE_SIZE;
    table->count = 0;
    table->buckets = calloc(table->size, sizeof(HashNode *));
    if (!table->buckets) {
        free(table);
        return NULL;
    }
    return table;
}

void hash_table_destroy(HashTable *table, void (*free_value)(void *)) {
    if (!table) return;

    for (size_t i = 0; i < table->size; i++) {
        HashNode *node = table->buckets[i];
        while (node) {
            HashNode *temp = node;
            node = node->next;
            free(temp->key);
            if (free_value) {
                free_value(temp->value);
            }
            free(temp);
        }
    }
    free(table->buckets);
    free(table);
}

bool hash_table_insert(HashTable *table, const char *key, void *value) {
    if (!table || !key) return false;

    if ((double)table->count / (double)table->size > LOAD_FACTOR_THRESHOLD) {
        hash_table_resize(table);
    }

    unsigned int index = hash(key) % table->size;
    HashNode *current = table->buckets[index];
    while (current) {
        if (strcmp(current->key, key) == 0) {
            current->value = value;
            return true;
        }
        current = current->next;
    }

    HashNode *new_node = malloc(sizeof(HashNode));
    if (!new_node) {
        return false;
    }
    new_node->key = strdup(key);
    if (!new_node->key) {
        free(new_node);
        return false;
    }
    new_node->value = value;
    new_node->next = table->buckets[index];
    table->buckets[index] = new_node;
    table->count++;
    return true;
}

bool hash_table_contains(const HashTable *table, const char *key) {
    if (!table || !key) return false;

    unsigned int index = hash(key) % table->size;
    HashNode *node = table->buckets[index];
    while (node) {
        if (strcmp(node->key, key) == 0) {
            return true;
        }
        node = node->next;
    }
    return false;
}

void *hash_table_get(const HashTable *table, const char *key) {
    if (!table || !key) return NULL;

    unsigned int index = hash(key) % table->size;
    HashNode *node = table->buckets[index];
    while (node) {
        if (strcmp(node->key, key) == 0) {
            return node->value;
        }
        node = node->next;
    }
    return NULL;
}

void hash_table_resize(HashTable *table) {
    if (!table) return;

    size_t new_size = table->size * 2;
    HashNode **new_buckets = calloc(new_size, sizeof(HashNode *));
    if (!new_buckets) {
        return;
    }

    for (size_t i = 0; i < table->size; i++) {
        HashNode *node = table->buckets[i];
        while (node) {
            HashNode *next_node = node->next;
            unsigned int new_index = hash(node->key) % new_size;
            node->next = new_buckets[new_index];
            new_buckets[new_index] = node;
            node = next_node;
        }
    }

    free(table->buckets);
    table->buckets = new_buckets;
    table->size = new_size;
}
