#ifndef RED_BYTE_SECURITY_ARSENAL_HASH_TABLE_H
#define RED_BYTE_SECURITY_ARSENAL_HASH_TABLE_H

#include <stdbool.h>
#include <stddef.h>

/**
 * Структура, представляющая узел хеш-таблицы.
 */
typedef struct HashNode {
    char *key;
    void *value;
    struct HashNode *next;
} HashNode;

/**
 * Структура, представляющая хеш-таблицу.
 */
typedef struct HashTable {
    HashNode **buckets;
    size_t size;
    size_t count;
} HashTable;

/**
 * Создает новую хеш-таблицу.
 *
 * @return Указатель на созданную хеш-таблицу, или NULL, если произошла ошибка.
 */
HashTable *hash_table_create(void);

/**
 * Уничтожает хеш-таблицу и освобождает всю связанную с ней память.
 *
 * @param table Указатель на хеш-таблицу, которую нужно уничтожить.
 * @param free_value Функция для освобождения памяти значений, или NULL, если освобождение не требуется.
 */
void hash_table_destroy(HashTable *table, void (*free_value)(void *));

/**
 * Вставляет новый элемент в хеш-таблицу.
 *
 * @param table Указатель на хеш-таблицу.
 * @param key Ключ для вставки.
 * @param value Значение, связанное с ключом.
 * @return true, если вставка прошла успешно, false в случае ошибки.
 */
bool hash_table_insert(HashTable *table, const char *key, void *value);

/**
 * Проверяет наличие ключа в хеш-таблице.
 *
 * @param table Указатель на хеш-таблицу.
 * @param key Ключ, который нужно проверить.
 * @return true, если ключ существует, false в противном случае.
 */
bool hash_table_contains(const HashTable *table, const char *key);

/**
 * Получает значение по указанному ключу из хеш-таблицы.
 *
 * @param table Указатель на хеш-таблицу.
 * @param key Ключ, значение которого нужно получить.
 * @return Указатель на значение, связанное с ключом, или NULL, если ключ не найден.
 */
void *hash_table_get(const HashTable *table, const char *key);

/**
 * Расширяет хеш-таблицу для уменьшения количества коллизий.
 *
 * @param table Указатель на хеш-таблицу, которую нужно расширить.
 */
void hash_table_resize(HashTable *table);

#endif // RED_BYTE_SECURITY_ARSENAL_HASH_TABLE_H
