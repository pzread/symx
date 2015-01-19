#include<stdint.h>
#include<assert.h>
#include<unistd.h>
#include<capstone/arm.h>
#include"context.h"
#include"state.h"
#include"expr.h"

#define LOG_PREFIX "ARM"

#define err(x,...) {fprintf(stderr,"[%d][" LOG_PREFIX "] " x,getpid(),##__VA_ARGS__);while(1);}
#define info(x,...) {fprintf(stderr,"[%d][" LOG_PREFIX "] " x,getpid(),##__VA_ARGS__);}

static int REG_MAP[ARM_REG_ENDING + 1] = {-1};
static refExpr imm41,imm44,imm48;

int arm_init(Context *ctx) {
        int i;

	ctx->reg_size = 4;
	ctx->num_reg = 16;
	ctx->num_flag = 4;

        for(i = 0; i < 13; i++) {
                REG_MAP[ARM_REG_R0 + i] = i;
        }
        REG_MAP[ARM_REG_SP] = 13;
        REG_MAP[ARM_REG_LR] = 14;
        REG_MAP[ARM_REG_PC] = 15;

	imm41 = BytVec::create_imm(4,1);
	imm44 = BytVec::create_imm(4,4);
	imm48 = BytVec::create_imm(4,8);

        return 0;
}

static refExpr get_op_expr(refBlock blk,cs_arm_op *op,uint64_t pc) {
	refExpr ret;
	if(op->type == ARM_OP_IMM) {
		ret = BytVec::create_imm(4,op->imm);
	}else if(op->type == ARM_OP_REG) {
		ret = blk->reg[REG_MAP[op->reg]];
	}
	switch(op->shift.type) {
	case ARM_SFT_INVALID:
		break;
	default:
		err("TODO");
		break;
	}
	return ret;
}
static refExpr get_cc_expr(refExpr expr,cs_arm *det) {
	if(det->cc == ARM_CC_INVALID) {
		return expr;
	}
	err("TODO");
	return expr;
}
static refMem get_cc_mem(refMem mem,cs_arm *det) {
	if(det->cc == ARM_CC_INVALID) {
		return mem;
	}
	err("TODO");
	return mem;
}
refBlock arm_emit(Context *ctx,uint8_t *bin,uint64_t pc,off_t off) {
	int i;
        refBlock blk = state_create_block(ctx);
	cs_insn *insn,*ins;
        size_t count;
        size_t idx;
        cs_arm *det;
        cs_arm_op *ops;

	refExpr xrd,xrs,xrt;
        
        count = cs_disasm(ctx->cs,bin + off,64,pc,0,&insn);
        ins = insn;
	for(idx = 0; idx < count; idx++) {
		info("%s %s\n",ins->mnemonic,ins->op_str);

		pc = ins->address;
                det = &ins->detail->arm;
                ops = det->operands;

                switch(ins->id) {
                case ARM_INS_PUSH:
			xrt = blk->reg[REG_MAP[ARM_REG_SP]];
			for(i = det->op_count - 1; i >= 0; i--) {
				xrt = expr_sub(xrt,imm44);
				xrs = get_op_expr(blk,&ops[i],pc);
				blk->mem = get_cc_mem(
						expr_store(blk->mem,xrt,xrs),
						det);
			}
			blk->reg[REG_MAP[ARM_REG_SP]] = get_cc_expr(xrt,det);
                        break;
                }

                break;
                ins += 1;
	}
	cs_free(insn,count);

        return blk;
}
