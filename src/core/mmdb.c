#include "core/mmdb.h"
#include "core/platform.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct mmdb_s {
    uint8_t*  data;
    size_t    file_size;
    uint32_t  data_section_start;
    uint32_t  node_count;
    uint32_t  record_size;
    uint32_t  node_size_bytes;
    int       ip_version;
};

static uint32_t read_u32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static uint32_t read_u16(const uint8_t* p) {
    return ((uint32_t)p[0] << 8) | (uint32_t)p[1];
}

/* Read a record from the tree.  Each node is 2*record_size bits.
   Bits are read big-endian across the byte boundary. */
static uint32_t tree_read_record(const mmdb* db, uint32_t node, int right) {
    uint32_t bit_off = node * db->record_size * 2 + (right ? db->record_size : 0);
    uint32_t byte_off = bit_off / 8;
    uint32_t bit_rem  = bit_off % 8;
    const uint8_t* p  = db->data + byte_off;
    uint32_t val      = 0;
    uint32_t bits     = db->record_size;

    if (byte_off + (bits + 7) / 8 > db->data_section_start) return 0;

    while (bits > 0) {
        uint32_t avail = 8 - bit_rem;
        uint32_t take  = bits < avail ? bits : avail;
        val = (val << take) | ((*p >> (avail - take)) & ((1u << take) - 1u));
        bits -= take;
        bit_rem = 0;
        p++;
    }
    return val;
}

/* Size encoding: lower 5 bits of control byte.
   0-28: literal, 29: +1 byte, 30: +2 bytes, 31: +4 bytes */
static uint32_t decode_size(const uint8_t* p, int* advance) {
    uint32_t sz = p[0] & 0x1fu;
    if (sz <= 28) { *advance = 1; return sz; }
    if (sz == 29) { *advance = 2; return 29 + p[1]; }
    if (sz == 30) { *advance = 3; return 285 + read_u16(p + 1); }
    *advance = 5;
    return 65821u + read_u32(p + 1);
}

/* Decode a pointer (type 1).  Returns offset within the data section. */
static uint32_t decode_pointer(const uint8_t* p, uint8_t ctrl, int* advance) {
    int      bytes   = (int)(((ctrl >> 3) & 3) + 1);
    uint32_t base_off = (ctrl & 7) == 1 ? 2048u :
                        (ctrl & 7) == 2 ? 526336u : 0;
    uint32_t val = 0;
    int i;
    for (i = 0; i < bytes; i++) val = (val << 8) | p[i];
    *advance = bytes;
    return val + base_off;
}

typedef enum { MMDB_MAP, MMDB_STRING, MMDB_POINTER, MMDB_UINT16,
               MMDB_UINT32, MMDB_OTHER } item_type_t;

typedef struct {
    item_type_t type;
    uint32_t    size;
    uint32_t    ptr_offset;
    const uint8_t* str_ptr;
    uint32_t    uint_val;
    int         advance;
} decoded_t;

static int decode_item(const uint8_t* data, decoded_t* out) {
    uint8_t ctrl     = data[0];
    int     raw_type = (ctrl >> 5) & 7;
    int     type     = raw_type;
    int     hdr      = 1;  /* bytes consumed by type tag */
    int     size_adv = 0;

    memset(out, 0, sizeof(*out));

    if (raw_type == 0) {
        ctrl = data[1];
        type = ((ctrl >> 5) & 7) + 7;
        hdr  = 2;
    }

    if (type == 1) {
        out->type       = MMDB_POINTER;
        out->ptr_offset = decode_pointer(data + hdr, ctrl, &out->advance);
        out->advance   += hdr;
        return 0;
    }

    out->size    = decode_size(data + hdr - 1, &size_adv);
    out->advance = hdr + size_adv - 1;  /* size_adv includes the size-byte itself */

    if (type == 2) {
        out->type    = MMDB_STRING;
        out->str_ptr = data + out->advance;
        out->advance += (int)out->size;
        return 0;
    }
    if (type == 5) {
        out->type     = MMDB_UINT16;
        out->uint_val = read_u16(data + out->advance);
        out->advance += 2;
        return 0;
    }
    if (type == 6) {
        out->type     = MMDB_UINT32;
        out->uint_val = read_u32(data + out->advance);
        out->advance += 4;
        return 0;
    }
    if (type == 7) {
        out->type = MMDB_MAP;
        return 0;
    }
    out->type     = MMDB_OTHER;
    out->advance += (int)out->size;
    return 0;
}

/* Return a pointer into the file given a data-section offset.
   Resolves one level of pointer indirection if the item is a pointer. */
static const uint8_t* resolve(const mmdb* db, uint32_t dsoff, uint32_t* end) {
    const uint8_t* p = db->data + db->data_section_start + dsoff;
    decoded_t item;
    decode_item(p, &item);
    if (item.type == MMDB_POINTER)
        p = db->data + db->data_section_start + item.ptr_offset;
    if (end && item.type == MMDB_POINTER) *end = (uint32_t)(p - db->data);
    else if (end) *end = db->data_section_start + dsoff + (uint32_t)item.advance;
    return p;
}

/* Read a string value from the data section. Returns pointer and length. */
static const uint8_t* read_string(const mmdb* db, uint32_t dsoff, uint32_t* len) {
    decoded_t item;
    const uint8_t* p = db->data + db->data_section_start + dsoff;
    decode_item(p, &item);
    if (item.type == MMDB_POINTER) {
        p = db->data + db->data_section_start + item.ptr_offset;
        decode_item(p, &item);
    }
    if (item.type == MMDB_STRING) {
        *len = item.size;
        return item.str_ptr;
    }
    *len = 0;
    return NULL;
}

/* Walk the map at `dsoff` to find the value for key `search_key`.
   Returns the data-section offset of the value, or -1 if not found.
   If the value is a pointer, it is NOT resolved — caller must resolve. */
static uint32_t map_find_key(const mmdb* db, uint32_t dsoff, const char* search_key) {
    const uint8_t* p;
    decoded_t map_item;
    uint32_t entries, i;

    p = resolve(db, dsoff, NULL);
    decode_item(p, &map_item);
    if (map_item.type != MMDB_MAP) return (uint32_t)-1;

    p += map_item.advance;
    entries = map_item.size;

    for (i = 0; i < entries; i++) {
        decoded_t key_item;
        const uint8_t* after_key;
        const uint8_t* key_ptr = NULL;
        uint32_t key_len = 0;

        /* decode key encoding at current position */
        decode_item(p, &key_item);
        after_key = p + key_item.advance;  /* value starts here */

        /* resolve the key string (may be inline or pointed to) */
        if (key_item.type == MMDB_POINTER) {
            const uint8_t* str_data =
                db->data + db->data_section_start + key_item.ptr_offset;
            decoded_t str_item;
            decode_item(str_data, &str_item);
            if (str_item.type == MMDB_STRING) {
                key_ptr = str_item.str_ptr;
                key_len = str_item.size;
            }
        } else if (key_item.type == MMDB_STRING) {
            key_ptr = key_item.str_ptr;
            key_len = key_item.size;
        }

        /* compute the data-section offset of the value (after_key) */
        uint32_t val_dsoff =
            (uint32_t)(after_key - db->data - db->data_section_start);

        /* skip over the value encoding to get to the next key */
        {
            decoded_t skip;
            decode_item(after_key, &skip);
            p = after_key + skip.advance;
        }

        if (key_ptr && key_len == strlen(search_key) &&
            memcmp(key_ptr, search_key, key_len) == 0)
            return val_dsoff;
    }

    return (uint32_t)-1;
}

static int parse_metadata(mmdb* db, uint32_t meta_off) {
    decoded_t item;
    uint32_t entries, i;
    const uint8_t* p = db->data + meta_off;

    if (meta_off + 2 > db->file_size) return -1;

    decode_item(p, &item);
    if (item.type != MMDB_MAP) return -1;
    p += item.advance;
    entries = item.size;

    for (i = 0; i < entries; i++) {
        decoded_t key_item, val_item;

        decode_item(p, &key_item);
        p += key_item.advance;
        decode_item(p, &val_item);
        p += val_item.advance;

        if (key_item.type == MMDB_STRING) {
            if (key_item.size == 10 &&
                memcmp(key_item.str_ptr, "node_count", 10) == 0)
                db->node_count = val_item.uint_val;
            else if (key_item.size == 11 &&
                     memcmp(key_item.str_ptr, "record_size", 11) == 0)
                db->record_size = val_item.uint_val;
            else if (key_item.size == 10 &&
                     memcmp(key_item.str_ptr, "ip_version", 10) == 0)
                db->ip_version = (int)val_item.uint_val;
        }
    }

    if (db->node_count == 0 || db->record_size == 0) return -1;
    db->node_size_bytes = db->record_size * 2 / 8;

    db->data_section_start = db->node_count * db->node_size_bytes;
    if (db->data_section_start >= db->file_size) return -1;

    return 0;
}

int mmdb_open(const char* path, mmdb** out) {
    FILE* fp = NULL;
    mmdb* db = NULL;
    size_t file_len;
    uint32_t meta_off;

    *out = NULL;

    fp = fopen(path, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    file_len = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_len < 32) { fclose(fp); return -1; }

    db = (mmdb*)calloc(1, sizeof(*db));
    if (!db) { fclose(fp); return -1; }

    db->data      = (uint8_t*)malloc(file_len);
    db->file_size = file_len;
    if (!db->data) { free(db); fclose(fp); return -1; }

    if (fread(db->data, 1, file_len, fp) != file_len) {
        mmdb_close(db); fclose(fp); return -1;
    }
    fclose(fp);

    /* Last 4 bytes = metadata offset (big-endian) */
    meta_off = read_u32(db->data + file_len - 4);
    /* 16 bytes before metadata are zero-padding,
       metadata must be between data_section and EOF */
    if (meta_off >= file_len - 4) { mmdb_close(db); return -1; }

    if (parse_metadata(db, meta_off) != 0) { mmdb_close(db); return -1; }

    *out = db;
    return 0;
}

void mmdb_close(mmdb* db) {
    if (!db) return;
    free(db->data);
    free(db);
}

int mmdb_lookup_country_code(mmdb* db, int family, const void* addr,
                              char* code, size_t code_size) {
    uint32_t node       = 0;
    int      max_bits   = family == AF_INET6 ? 128 : 32;
    uint8_t  ip[16];
    int      i;
    const uint8_t* val_str;
    uint32_t val_len;

    if (!db || !addr || !code || code_size == 0) return -1;
    code[0] = '\0';

    memset(ip, 0, sizeof(ip));

    if (family == AF_INET) {
        /* IPv4 lookup in v6 database: prepend ::ffff:0:0/96 prefix */
        if (db->ip_version == 6) {
            ip[10] = 0xff; ip[11] = 0xff;
            memcpy(ip + 12, addr, 4);
        } else {
            memcpy(ip, addr, 4);
        }
    } else {
        memcpy(ip, addr, 16);
    }

    max_bits = db->ip_version == 6 ? 128 : 32;

    for (i = 0; i < max_bits && node < db->node_count; i++) {
        int bit   = (ip[i / 8] >> (7 - (i % 8))) & 1;
        uint32_t rec = tree_read_record(db, node, bit);
        if (rec == db->node_count) return -1;
        if (rec > db->node_count) {
            uint32_t dsoff = rec - db->node_count;
            uint32_t country_dsoff;

            country_dsoff = map_find_key(db, dsoff, "country");
            if (country_dsoff == (uint32_t)-1) return -1;

            dsoff = map_find_key(db, country_dsoff, "iso_code");
            if (dsoff == (uint32_t)-1) return -1;

            val_str = read_string(db, dsoff, &val_len);
            if (!val_str || val_len < 2) return -1;

            if (val_len >= code_size) val_len = (uint32_t)(code_size - 1);
            memcpy(code, val_str, val_len);
            code[val_len] = '\0';
            return 0;
        }
        node = rec;
    }

    return -1;
}
