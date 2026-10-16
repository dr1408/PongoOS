/* In-place DeviceTree property inspection and editing commands. */
#include "dt_write.h"
#include "pongo.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DT_EDIT_GROWTH 0x4000

static size_t dt_edit_capacity;

static uint64_t dt_ptr_to_xnu_va(const void *ptr)
{
    return (uint64_t)ptr - kCacheableView + 0x800000000ULL
         - gBootArgs->physBase + gBootArgs->virtBase;
}

static bool dt_ensure_edit_capacity(size_t extra)
{
    size_t old_len = gBootArgs->deviceTreeLength;
    if (dt_edit_capacity && old_len + extra <= dt_edit_capacity)
        return true;

    size_t wanted = old_len + extra + DT_EDIT_GROWTH;
    if (wanted > UINT32_MAX) {
        iprintf("DeviceTree is too large to relocate\n");
        return false;
    }

    void *new_tree = alloc_static((uint32_t)wanted);
    if (!new_tree) {
        iprintf("failed to allocate persistent DeviceTree storage\n");
        return false;
    }
    memcpy(new_tree, gDeviceTree, old_len);
    gDeviceTree = new_tree;
    gBootArgs->deviceTreeP = (void *)dt_ptr_to_xnu_va(new_tree);
    dt_edit_capacity = wanted;
    return true;
}

static dt_prop_t *dt_find_prop_header(dt_node_t *node, const char *key)
{
    if (!node || !key || strlen(key) >= DT_KEY_LEN)
        return NULL;

    size_t off = sizeof(*node);
    for (uint32_t i = 0; i < node->nprop; ++i) {
        dt_prop_t *prop = (dt_prop_t *)((uintptr_t)node + off);
        size_t len = prop->len & 0xffffff;
        if (strncmp(prop->key, key, DT_KEY_LEN) == 0)
            return prop;
        off += sizeof(*prop) + ((len + 3) & ~(size_t)3);
    }
    return NULL;
}

static dt_node_t *dt_resolve_node(const char *name)
{
    if (!gDeviceTree || !name || !*name)
        return NULL;
    return dt_find(gDeviceTree, name);
}

static void dt_dump_value(const uint8_t *value, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        iprintf("%04zx: ", i);
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len)
                iprintf("%02x ", value[i + j]);
            else
                iprintf("   ");
        }
        iprintf("|");
        for (size_t j = 0; j < 16 && i + j < len; ++j) {
            uint8_t c = value[i + j];
            iprintf("%c", c >= 0x20 && c < 0x7f ? c : '.');
        }
        iprintf("|\n");
    }
}

static bool dt_printable(const uint8_t *value, size_t len)
{
    if (!len)
        return false;
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = value[i];
        if (c == 0 && i == len - 1)
            continue;
        if ((c < 0x20 || c >= 0x7f) && c != '\t' && c != '\n')
            return false;
    }
    return true;
}

static int dt_hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool dt_parse_hex(const char *hex, uint8_t *bytes, size_t bytes_size,
                         size_t *value_len)
{
    if (!hex || !*hex) {
        *value_len = 0;
        return true;
    }
    size_t hex_len = strlen(hex);
    if ((hex_len & 1) || hex_len / 2 > bytes_size) {
        iprintf("hex input must have an even length and be at most %zu digits\n",
                bytes_size * 2);
        return false;
    }
    *value_len = hex_len / 2;
    for (size_t i = 0; i < *value_len; ++i) {
        int hi = dt_hex_nibble(hex[2 * i]);
        int lo = dt_hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            iprintf("invalid hex at character %zu\n", 2 * i + (hi >= 0));
            return false;
        }
        bytes[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

void dt_add_cmd(const char *cmd, char *args)
{
    if (!args || !*args) {
        iprintf("Usage: dtadd <node-name-or-path> <property> [hex-bytes]\n");
        return;
    }
    char *node_name = args;
    char *key = command_tokenize(args, 0x1ff - (uint32_t)(args - cmd));
    char *hex = key ? command_tokenize(key, 0x1ff - (uint32_t)(key - cmd)) : NULL;
    if (!key || !*node_name || !*key) {
        iprintf("Usage: dtadd <node-name-or-path> <property> [hex-bytes]\n");
        return;
    }
    if (strlen(key) >= DT_KEY_LEN) {
        iprintf("property keys must be shorter than %d characters\n", DT_KEY_LEN);
        return;
    }

    uint8_t bytes[256];
    size_t value_len = 0;
    if (!dt_parse_hex(hex, bytes, sizeof(bytes), &value_len))
        return;
    size_t value_padded = (value_len + 3) & ~(size_t)3;
    size_t record_size = sizeof(dt_prop_t) + value_padded;

    dt_node_t *node = dt_resolve_node(node_name);
    if (!node) {
        iprintf("DeviceTree node not found: %s\n", node_name);
        return;
    }
    if (dt_find_prop_header(node, key)) {
        iprintf("DeviceTree property already exists: %s/%s\n", node_name, key);
        return;
    }

    /* Relocation invalidates node, so resolve it again afterwards. */
    if (!dt_ensure_edit_capacity(record_size))
        return;
    node = dt_resolve_node(node_name);
    if (!node) {
        iprintf("DeviceTree node disappeared after relocation: %s\n", node_name);
        return;
    }

    size_t insert_off = sizeof(*node);
    for (uint32_t i = 0; i < node->nprop; ++i) {
        dt_prop_t *prop = (dt_prop_t *)((uintptr_t)node + insert_off);
        size_t len = prop->len & 0xffffff;
        insert_off += sizeof(*prop) + ((len + 3) & ~(size_t)3);
    }
    uint8_t *insert = (uint8_t *)node + insert_off;
    uint8_t *tree_end = (uint8_t *)gDeviceTree + gBootArgs->deviceTreeLength;
    if (insert > tree_end) {
        iprintf("invalid DeviceTree insertion point\n");
        return;
    }

    size_t tail_size = (size_t)(tree_end - insert);
    uint32_t old_tree_len = gBootArgs->deviceTreeLength;
    memmove(insert + record_size, insert, tail_size);
    dt_prop_t *added = (dt_prop_t *)insert;
    memset(added, 0, record_size);
    memcpy(added->key, key, strlen(key));
    added->len = (uint32_t)value_len;
    if (value_len)
        memcpy(added->val, bytes, value_len);
    node->nprop++;
    gBootArgs->deviceTreeLength += (uint32_t)record_size;

    if (dt_check(gDeviceTree, gBootArgs->deviceTreeLength, NULL) != 0) {
        node->nprop--;
        memmove(insert, insert + record_size, tail_size);
        gBootArgs->deviceTreeLength = old_tree_len;
        iprintf("DeviceTree validation failed after adding property\n");
        return;
    }
    iprintf("added %s/%s (%zu bytes); DeviceTree length is now 0x%x\n",
            node_name, key, value_len, gBootArgs->deviceTreeLength);
}

void dt_read_cmd(const char *cmd, char *args)
{
    if (!args || !*args) {
        iprintf("Usage: dtread <node-name-or-path> <property>\n");
        return;
    }
    char *node_name = args;
    char *key = command_tokenize(args, 0x1ff - (uint32_t)(args - cmd));
    if (!key || !*node_name || !*key) {
        iprintf("Usage: dtread <node-name-or-path> <property>\n");
        return;
    }
    dt_node_t *node = dt_resolve_node(node_name);
    size_t len = 0;
    void *value = node ? dt_prop(node, key, &len) : NULL;
    if (!value) {
        iprintf("DeviceTree property not found: %s/%s\n", node_name, key);
        return;
    }
    iprintf("%s/%s (%zu bytes)\n", node_name, key, len);
    if (dt_printable(value, len))
        iprintf("String: %.*s\n", (int)len, (const char *)value);
    dt_dump_value(value, len);
}

void dt_write_cmd(const char *cmd, char *args)
{
    if (!args || !*args) {
        iprintf("Usage: dtwrite <node-name-or-path> <property> <hex-bytes>\n");
        return;
    }
    char *node_name = args;
    char *key = command_tokenize(args, 0x1ff - (uint32_t)(args - cmd));
    char *hex = key ? command_tokenize(key, 0x1ff - (uint32_t)(key - cmd)) : NULL;
    if (!key || !hex || !*node_name || !*key || !*hex) {
        iprintf("Usage: dtwrite <node-name-or-path> <property> <hex-bytes>\n");
        return;
    }
    size_t hex_len = strlen(hex);
    if ((hex_len & 1) || hex_len / 2 > 256) {
        iprintf("hex input must have an even length and be at most 512 digits\n");
        return;
    }
    uint8_t bytes[256];
    size_t value_len = hex_len / 2;
    for (size_t i = 0; i < value_len; ++i) {
        int hi = dt_hex_nibble(hex[2 * i]);
        int lo = dt_hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            iprintf("invalid hex at character %zu\n", 2 * i + (hi >= 0));
            return;
        }
        bytes[i] = (uint8_t)((hi << 4) | lo);
    }

    dt_node_t *node = dt_resolve_node(node_name);
    dt_prop_t *prop = dt_find_prop_header(node, key);
    if (!prop) {
        iprintf("DeviceTree property not found: %s/%s\n", node_name, key);
        return;
    }
    size_t old_len = prop->len & 0xffffff;
    size_t old_padded = (old_len + 3) & ~(size_t)3;
    size_t new_padded = (value_len + 3) & ~(size_t)3;
    if (old_padded != new_padded) {
        iprintf("refusing size change: old=%zu bytes (padded %zu), new=%zu bytes (padded %zu)\n",
                old_len, old_padded, value_len, new_padded);
        return;
    }
    uint8_t *dst = (uint8_t *)prop->val;
    if (value_len)
        memcpy(dst, bytes, value_len);
    if (new_padded > value_len)
        memset(dst + value_len, 0, new_padded - value_len);
    prop->len = (prop->len & 0xff000000) | (uint32_t)value_len;
    iprintf("updated %s/%s (%zu bytes)\n", node_name, key, value_len);
}

void dt_rename_cmd(const char *cmd, char *args)
{
    if (!args || !*args) {
        iprintf("Usage: dtrename <node-name-or-path> <old-key> <new-key>\n");
        return;
    }
    char *node_name = args;
    char *old_key = command_tokenize(args, 0x1ff - (uint32_t)(args - cmd));
    char *new_key = old_key ? command_tokenize(old_key, 0x1ff - (uint32_t)(old_key - cmd)) : NULL;
    if (!old_key || !new_key || !*node_name || !*old_key || !*new_key) {
        iprintf("Usage: dtrename <node-name-or-path> <old-key> <new-key>\n");
        return;
    }
    if (strlen(old_key) >= DT_KEY_LEN || strlen(new_key) >= DT_KEY_LEN) {
        iprintf("property keys must be shorter than %d characters\n", DT_KEY_LEN);
        return;
    }
    dt_node_t *node = dt_resolve_node(node_name);
    dt_prop_t *prop = dt_find_prop_header(node, old_key);
    if (!prop) {
        iprintf("DeviceTree property not found: %s/%s\n", node_name, old_key);
        return;
    }
    if (strcmp(old_key, new_key) == 0) {
        iprintf("property key is unchanged\n");
        return;
    }
    if (dt_find_prop_header(node, new_key)) {
        iprintf("target property already exists: %s\n", new_key);
        return;
    }
    memset(prop->key, 0, sizeof(prop->key));
    memcpy(prop->key, new_key, strlen(new_key));
    iprintf("renamed %s/%s to %s\n", node_name, old_key, new_key);
}
