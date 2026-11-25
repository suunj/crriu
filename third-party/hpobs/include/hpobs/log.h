/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef HPOBS_LOG_H_
#define HPOBS_LOG_H_

namespace hpobs {

// Messages go to stderr as "<prefix>: <text>\n". The prefix defaults to
// "hpobs"; a host tool sets its own name.
void set_log_prefix(const char* prefix);
const char* log_prefix();
void logf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

}  // namespace hpobs

#endif /* HPOBS_LOG_H_ */
