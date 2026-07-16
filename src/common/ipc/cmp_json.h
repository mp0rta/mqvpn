// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/common/ipc/cmp_json.h — bounded append-only JSON writer + minimal
 * array-membership helper for CMP.
 *
 * No OS / libevent / libmqvpn dependencies allowed here (mirrors
 * cmp_types.h). Emission-side counterpart to src/json_mini.h's parsing
 * helpers.
 */
#ifndef MQVPN_CMP_JSON_H
#define MQVPN_CMP_JSON_H
#include <stddef.h>

/* Bounded append-only writer. overflow 後の書き込みは無視され、
 * overflow flag が立つ (truncated JSON を絶対に送らないための仕掛け)。 */
typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    int overflow;
} cmp_buf_t;

void cmp_buf_init(cmp_buf_t *b, char *storage, size_t cap);
/* printf-style append。fmt に %s で外部由来文字列を渡すのは禁止
 * (escape を通らないため) — 文字列値は cmp_json_append_str を使う。 */
void cmp_buf_appendf(cmp_buf_t *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
/* JSON string literal を quote 込みで append する。
 * ", \\, および U+0000–U+001F を \n/\r/\t/\uXXXX へ escape。
 * それ以外のバイト (UTF-8 継続バイト含む) は素通し。 */
void cmp_json_append_str(cmp_buf_t *b, const char *s);

/* json_mini.h には配列 parser が無いため、Phase 1 に必要な最小ヘルパを
 * ここに置く: key の値が JSON 配列で、その中に文字列要素 want が含まれるか。
 * 例: cmp_json_array_contains_str(req, "supported_protocols", "1.0")。
 * 配列でない/欠落は 0。ネスト配列・object 要素は非対応 (CMP では出現しない)。 */
int cmp_json_array_contains_str(const char *json, const char *key, const char *want);

#endif
