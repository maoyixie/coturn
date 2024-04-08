#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apputils.h"
#include "ns_turn_utils.h"
#include "stun_buffer.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 12) {
    return 0;
  }

  uint8_t buf[Size];
  memcpy(buf, Data, Size);

  // Split the input data into the necessary fields.
  size_t uname_len = Size / 4;
  size_t realm_len = Size / 4;
  size_t upwd_len = Size - uname_len - realm_len;

  uint8_t uname[uname_len + 1];
  uint8_t realm[realm_len + 1];
  uint8_t upwd[upwd_len + 1];

  memcpy(uname, Data, uname_len);
  memcpy(realm, Data + uname_len, realm_len);
  memcpy(upwd, Data + uname_len + realm_len, upwd_len);

  uname[uname_len] = '\0';
  realm[realm_len] = '\0';
  upwd[upwd_len] = '\0';

  // Fuzz the function with various combinations of credential type and SHA type.
  for (int ct = 0; ct <= 2; ct++) {
    for (int sha = 0; sha <= 2; sha++) {
      turn_credential_type credential_type = (turn_credential_type)ct;
      SHATYPE shatype = (SHATYPE)sha;
      stun_check_message_integrity_str(credential_type, buf, Size, uname, realm, upwd, shatype);
    }
  }

  return 0;
}