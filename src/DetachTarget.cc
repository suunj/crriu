/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachTarget.h"

#include <stdio.h>
#include <stdlib.h>

using namespace std;

namespace rr {

Target parse_target(const string& spec) {
  Target t;
  t.text = spec;
  if (!spec.empty() && spec.find_first_not_of("0123456789") == string::npos) {
    t.event = strtoll(spec.c_str(), nullptr, 10);
    return t;
  }
  size_t colon = spec.rfind(':');
  if (colon != string::npos && colon > 2) {        // "sym:N" / "0x..:N", not "::"
    t.hit = strtol(spec.c_str() + colon + 1, nullptr, 10);
    if (t.hit < 1) t.hit = 1;
    t.symbol = spec.substr(0, colon);
  } else {
    t.symbol = spec;
  }
  return t;
}

Dump parse_dump(const string& spec) {
  Dump d;
  d.every = 1;
  size_t a = spec.find(':');
  size_t b = a == string::npos ? a : spec.find(':', a + 1);

  if (a == string::npos || b == string::npos) {
    fprintf(stderr, "rr detach: -d expects NAME:ADDR:LEN[:EVERY], got '%s'\n", spec.c_str());
    exit(1);
  }
  d.name = spec.substr(0, a);
  d.addr = strtoull(spec.c_str() + a + 1, nullptr, 0);
  size_t c = spec.find(':', b + 1);
  d.len = strtoull(spec.substr(b + 1, c == string::npos ? string::npos : c - b - 1).c_str(), nullptr, 0);

  if (c != string::npos) {
    d.every = strtol(spec.c_str() + c + 1, nullptr, 0);
    size_t e = spec.find(':', c + 1);
    if (e != string::npos)
        d.from = strtol(spec.c_str() + e + 1, nullptr, 0);
  }
  if (d.every < 1)
      d.every = 1;

  return d;
}

} // namespace rr
