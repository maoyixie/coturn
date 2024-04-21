#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apputils.h"
#include "ns_turn_utils.h"
#include "stun_buffer.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  int result, fingerprint_present;

  if (Size < sizeof(uint32_t)) {
    return 0;
  }

  // Modify the size to fit the required range for STUN message (20 to 1200 bytes)
  size_t adjustedSize = 20 + (Size % (1200 - 20));

  // Create a buffer with the adjusted size and copy the input data into it
  uint8_t *buf = (uint8_t *)malloc(adjustedSize);
  if (!buf) {
    return 0;
  }
  memcpy(buf, Data, Size); // bug: heap buffer overflow
  memset(buf + Size, 0, adjustedSize - Size);

  // Fuzz the target function
  result = stun_is_command_message_full_check_str(buf, adjustedSize, 0, &fingerprint_present);

  free(buf);
  return 0;
}