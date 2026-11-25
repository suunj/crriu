/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachTarget.h"

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
    if (t.hit < 1) {
      t.hit = 1;
    }
    t.symbol = spec.substr(0, colon);
  } else {
    t.symbol = spec;
  }
  return t;
}

} // namespace rr
