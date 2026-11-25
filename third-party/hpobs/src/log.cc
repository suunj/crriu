/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "hpobs/log.h"

#include <stdarg.h>
#include <stdio.h>

#include <string>

namespace hpobs {

static std::string& prefix_storage() {
  static std::string p = "hpobs";
  return p;
}

void set_log_prefix(const char* prefix) {
  prefix_storage() = prefix;
}

const char* log_prefix() {
  return prefix_storage().c_str();
}

void logf(const char* fmt, ...) {
  fprintf(stderr, "%s: ", log_prefix());
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

}  // namespace hpobs
