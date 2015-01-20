#include<stdint.h>

#include"context.h"
#include"state.h"

#ifndef _ARM_H_
#define _ARM_H_

#define ARM_REG_SIZE 4
#define ARM_FLAG_NUM 32
#define ARM_SR_N 31
#define ARM_SR_Z 31
#define ARM_SR_C 31
#define ARM_SV_N 31

int arm_init(Context *ctx);
refBlock arm_emit(Context *ctx,uint8_t *bin,uint64_t base,off_t off);

#endif
