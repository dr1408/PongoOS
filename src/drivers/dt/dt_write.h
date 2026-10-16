#ifndef DT_WRITE_H
#define DT_WRITE_H

#include "dt.h"
#include <stddef.h>

void dt_read_cmd(const char *cmd, char *args);
void dt_write_cmd(const char *cmd, char *args);
void dt_rename_cmd(const char *cmd, char *args);
void dt_add_cmd(const char *cmd, char *args);

#endif
