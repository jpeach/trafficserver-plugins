#include <stdio.h>
#include <stdarg.h>

#include "print_funcs.h"

static const int LINE_SIZE = 1024 * 1024;

void Debug(const char *tag, const char *fmt, ...) {
  char buf[LINE_SIZE];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, LINE_SIZE, fmt, ap);
  printf("Debug (%s): %s\n", tag, buf);
  va_end(ap);
}

void Error(const char *fmt, ...) {
  char buf[LINE_SIZE];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, LINE_SIZE, fmt, ap);
  printf("Error: %s\n", buf);
  va_end(ap);
}
