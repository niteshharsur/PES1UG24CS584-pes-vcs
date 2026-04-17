// tree.c — Tree object serialization and construction

#include "tree.h"
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define MODE_FILE 0100644
#define MODE_EXEC 0100755
#define MODE_DIR  0040000

uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode)) return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;

    const uint8_t *ptr = data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1;

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        memcpy(mode_str, ptr, mode_len);

        entry->mode = strtol(mode_str, NULL, 8);
        ptr = space + 1;

        const uint8_t *nullb = memchr(ptr, '\0', end - ptr);
        if (!nullb) return -1;

        size_t name_len = nullb - ptr;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';

        ptr = nullb + 1;

        if (ptr + HASH_SIZE > end) return -1;

        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }

    return 0;
}

static int cmp_entries(const void *a, const void *b) {
    return strcmp(((TreeEntry *)a)->name, ((TreeEntry *)b)->name);
}

int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    size_t max = tree->count * 296;

    uint8_t *buf = malloc(max);
    if (!buf) return -1;

    Tree sorted = *tree;

    qsort(sorted.entries, sorted.count, sizeof(TreeEntry), cmp_entries);

    size_t off = 0;

    for (int i = 0; i < sorted.count; i++) {
        TreeEntry *e = &sorted.entries[i];

        int written = sprintf((char *)buf + off, "%o %s", e->mode, e->name);
        off += written + 1;

        memcpy(buf + off, e->hash.hash, HASH_SIZE);
        off += HASH_SIZE;
    }

    *data_out = buf;
    *len_out = off;

    return 0;
}

int tree_from_index(ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    void *data = NULL;
    size_t len = 0;

    if (tree_serialize(&tree, &data, &len) != 0)
        return -1;

    int rc = object_write(OBJ_TREE, data, len, id_out);

    free(data);
    return rc;
}
