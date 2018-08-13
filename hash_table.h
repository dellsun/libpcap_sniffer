#ifndef _H_HASH_TABLE
#define _H_HASH_TABLE

#define HASH_TABLE_MAX_SIZE 10000

typedef struct HashNode_Struct HashNode;

struct HashNode_Struct
{
    char *key;
    long value;
    HashNode* pNext;
};

void hash_table_init();
unsigned int hash_table_hash_str(const char* skey);
void hash_table_insert(const char *key, long value);
void hash_table_remove(const char *key);
HashNode* hash_table_find(const char* skey);
void hash_table_print();
void hash_table_release();

#endif
