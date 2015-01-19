#include<stdint.h>
#include"context.h"
#include"state.h"

#ifndef _ARM_EMIT_H_
#define _ARM_EMIT_H_

int arm_init(Context *ctx);
refBlock arm_emit(Context *ctx,uint8_t *bin,uint64_t base,off_t off);

#endif
