#include "api/utils.h"

#define R_UTILS_HASH_SIZE 0x30000

static u32 r_utils_hash(const u8 *key, size_t key_len) {
  u32 hash;
  u32 i;

  hash = 0;

  for(i = 0; i < key_len; i++) {
    hash = (hash << 1) | (hash >> 31);
    hash += key[i];
  }
  return hash % R_UTILS_HASH_SIZE;
}

void r_utils_hash_foreach(r_utils_hash_s *h, void (*callback)(r_utils_hash_elem_s*)) {
  u32 i;
  r_utils_hash_elem_s *elem;

  assert(h != NULL);
  assert(h->elems != NULL);

  for(i = 0; i < R_UTILS_HASH_SIZE; i++) {
    for(elem = h->elems[i]; elem; elem = elem->next) {
      callback(elem);
    }
  }
}

/* Free hashtable */
void r_utils_hash_free(r_utils_hash_s **h) {
  r_utils_hash_elem_s *e, *tmp;
  u32 i;

  assert(h != NULL && *h != NULL);
  assert((*h)->elems != NULL);

  for(i = 0; i < R_UTILS_HASH_SIZE; i++) {
    e = (*h)->elems[i];
    while(e != NULL) {
      tmp = e->next;
      if((*h)->elem_destructor)
      	(*h)->elem_destructor(e->val);
      free(e->key);
      free(e);
      e = tmp;
    }
  }

  free((*h)->elems);
  free(*h);
  *h = NULL;
}

r_utils_hash_elem_s* r_utils_hash_elem_new(void *elem, u8 *key, u32 key_len) {
  r_utils_hash_elem_s *e;

  e = r_utils_malloc(sizeof(*e));

  e->val = elem;
  e->key = key;
  e->key_len = key_len;

  return e;
}

/* Allocate hashtable */
r_utils_hash_s* r_utils_hash_new(void(*destructor)(void*)) {
  r_utils_hash_s *h;

  h = r_utils_calloc(1, sizeof(*h));
  h->elems = r_utils_calloc(R_UTILS_HASH_SIZE, sizeof(r_utils_hash_elem_s*));
  h->elem_destructor = destructor;

  return h;
}

/* Insert an element to the hashtable */
void r_utils_hash_insert(r_utils_hash_s *h, r_utils_hash_elem_s *elem) {
  u32 hash;

  assert(h != NULL);
  assert(elem != NULL);
  assert(h->elems != NULL);

  hash = r_utils_hash(elem->key, elem->key_len);

  if(h->elems[hash] != NULL)
    h->colisions++;

  elem->next = h->elems[hash];
  h->elems[hash] = elem;
  h->size++;
}

/* Find an element in the hashtable, and compare with the function cmp */
r_utils_hash_elem_s* r_utils_hash_find_elem(const r_utils_hash_s *h, int (*cmp)(r_utils_hash_elem_s*, const void*), const void *user) {
  r_utils_hash_elem_s *e;
  int i;

  assert(h != NULL);
  assert(h->elems != NULL);
  assert(cmp != NULL);

  for(i = 0; i < R_UTILS_HASH_SIZE; i++) {
    for(e = h->elems[i]; e; e = e->next) {
      if(cmp(e, user))
	return e;
    }
  }
  return NULL;
}


/* Return true the key match an element */
int r_utils_hash_elem_exist(r_utils_hash_s *h, u8 *key, u32 key_len) {
  r_utils_hash_elem_s *e;
  u32 hash;

  assert(h != NULL);
  assert(h->elems != NULL);
  assert(key != NULL);

  hash = r_utils_hash(key, key_len);

  for(e = h->elems[hash]; e; e = e->next) {
    if(e->key_len == key_len)
      if(!memcmp(e->key, key, key_len))
	return 1;
  }
  return 0;
}

/* Return the size of the hashtable (number of elements) */
u32 r_utils_hash_size(r_utils_hash_s *h) {
  assert(h != NULL);
  return h->size;
}
