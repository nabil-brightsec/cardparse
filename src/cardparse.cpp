// cardparse - a tiny contact card (.card) parser.
//
// Reads a simple line based ".card" file and prints the parsed record.
// A few directives let a card store binary data and export itself to disk.
//
// This is a small sample application meant to be used as a fuzzing target.
// It is written in a deliberately naive style and contains memory safety
// and input validation bugs. It is not meant for production use.

#include "cardparse.h"

#include <cstdlib>
#include <cstring>

// Strip a trailing newline (and carriage return) in place.
void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

// Copy a field value into a fixed destination buffer.
// The value length is never checked against the destination size.
void set_field(char *dst, const char *value) {
    strcpy(dst, value);
}

// Decode a "data:<len>:<bytes>" record into a small working buffer.
// The length is read from the record and trusted as-is.
void load_data(const char *spec) {
    char buf[32];
    long len = strtol(spec, nullptr, 10);
    const char *payload = strchr(spec, ':');
    if (!payload) {
        return;
    }
    payload++; // skip the ':' separator
    for (long i = 0; i < len; i++) {
        buf[i] = payload[i]; // no bounds check against sizeof(buf)
    }
    printf("loaded %ld bytes of data\n", len);
}

// Write the current card to a path taken from the file.
// The path is used exactly as supplied.
void save_card(const Card *c, const char *path) {
    if (!path || path[0] == '\0' || path[0] == '/' || path[0] == '\\' ||
        (path[0] && path[1] == ':')) {
        return;
    }

    // Do not allow a relative path to walk outside the working directory.
    for (const char *part = path; *part;) {
        const char *end = part;
        while (*end && *end != '/' && *end != '\\') {
            ++end;
        }
        if (end - part == 2 && part[0] == '.' && part[1] == '.') {
            return;
        }
        part = *end ? end + 1 : end;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "cannot open %s for writing\n", path);
        return;
    }
    fprintf(f, "name=%s\ntitle=%s\nnote=%s\n", c->name, c->title, c->note);
    fclose(f);
    printf("saved card to %s\n", path);
}

// Parse a stream of "key:value" lines into a single card.
void parse_stream(FILE *in) {
    Card card;
    memset(&card, 0, sizeof(card));

    char line[1024];
    while (fgets(line, sizeof(line), in)) {
        trim_newline(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        char *sep = strchr(line, ':');
        if (!sep) {
            continue;
        }
        *sep = '\0';
        const char *key = line;
        const char *value = sep + 1;

        if (strcmp(key, "name") == 0) {
            set_field(card.name, value);
        } else if (strcmp(key, "title") == 0) {
            set_field(card.title, value);
        } else if (strcmp(key, "note") == 0) {
            set_field(card.note, value);
        } else if (strcmp(key, "data") == 0) {
            load_data(value);
        } else if (strcmp(key, "save") == 0) {
            save_card(&card, value);
        }
    }

    printf("card: name=%s title=%s\n", card.name, card.title);
}
