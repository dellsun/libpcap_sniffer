#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash_table.h"
 
HashNode* hashTable[HASH_TABLE_MAX_SIZE]; 
int hash_table_size;  
 
void hash_table_init()
{
	hash_table_size = 0;
	memset(hashTable, 0, sizeof(HashNode*) * HASH_TABLE_MAX_SIZE);
}
 
unsigned int hash_table_hash_str(const char* skey)
{
	const signed char *p = (const signed char*)skey;
    	unsigned int h = *p;
    	if(h)
    	{
        	for(p += 1; *p != '\0'; ++p)
            		h = (h << 5) - h + *p;
    	}
    	return h;
}
 
void hash_table_insert(const char *key, long value)
{
    	if(hash_table_size >= HASH_TABLE_MAX_SIZE)
    	{
        	//printf("out of hash table memory!\n");
        	return;
    	}
 
    	unsigned int pos = hash_table_hash_str(key) % HASH_TABLE_MAX_SIZE;
 
   	HashNode* pHead = hashTable[pos];
    	while(pHead)
    	{
        	if(strcmp(pHead->key, key) == 0)
        	{
            		return;
        	}
        	pHead = pHead->pNext;
    	}
 
    	HashNode* pNewNode = (HashNode*)malloc(sizeof(HashNode));
    	memset(pNewNode, 0, sizeof(HashNode));
    
    	pNewNode->key = (char*)malloc(sizeof(char) * (strlen(key) + 1));
    	strcpy(pNewNode->key, key);
    	pNewNode->value = value;
 
   	pNewNode->pNext = hashTable[pos];
    	hashTable[pos] = pNewNode;
	
    	hash_table_size++;
}

void hash_table_remove(const char *key)
{
    	unsigned int pos = hash_table_hash_str(key) % HASH_TABLE_MAX_SIZE;
    	if(hashTable[pos])
    	{
        	HashNode* pHead = hashTable[pos];
        	HashNode* pLast = NULL;
        	HashNode* pRemove = NULL;
        	while(pHead)
        	{
            		if(strcmp(key, pHead->key) == 0)
            		{
                		pRemove = pHead;
                		break;
            		}
            		pLast = pHead;
            		pHead = pHead->pNext;
        	}
        	if(pRemove)
        	{
            		if(pLast)
                		pLast->pNext = pRemove->pNext;
            		else
                		hashTable[pos] = pRemove->pNext;
 
            		free(pRemove->key);
            		free(pRemove);
        	}
    	}
}
 
HashNode* hash_table_find(const char* key)
{
    	unsigned int pos = hash_table_hash_str(key) % HASH_TABLE_MAX_SIZE;
    	if(hashTable[pos])
    	{
        	HashNode* pHead = hashTable[pos];
        	while(pHead)
        	{
            		if(strcmp(key, pHead->key) == 0)
                		return pHead;
            		pHead = pHead->pNext;
        	}
    	}

    	return NULL;
}


void hash_table_print()
{
    	int i;
    	for(i = 0; i < HASH_TABLE_MAX_SIZE; ++i)
    	{
        	if(hashTable[i])
        	{
            		HashNode* pHead = hashTable[i];
            		while(pHead)
            		{
                		printf("%d  %s\n", pHead->value, pHead->key);
                		pHead = pHead->pNext;
            		}
        	}
    	}
}

void hash_table_release()
{
    	int i;
    	for(i = 0; i < HASH_TABLE_MAX_SIZE; ++i)
    	{
        	if(hashTable[i])
        	{
            		HashNode* pHead = hashTable[i];
           		while(pHead)
            		{
                		HashNode* pTemp = pHead;
                		pHead = pHead->pNext;
                		if(pTemp)
                		{
                    			free(pTemp->key);
                    			free(pTemp);
                		}
 
            		}	
        	}
    	}
}
