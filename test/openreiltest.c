#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<libopenreil.h>

#define MAX_ARG_STR 50

const char *inst_op[] =
{
    "NONE", "UNK", "JCC",
    "STR", "STM", "LDM",
    "ADD", "SUB", "NEG", "MUL", "DIV", "MOD", "SMUL", "SDIV", "SMOD",
    "SHL", "SHR", "AND", "OR", "XOR", "NOT",
    "EQ", "LT"
};

int arg_size[] = { 1, 8, 16, 32, 64 };

char *arg_print(reil_arg_t *arg, char *arg_str)
{
    memset(arg_str, 0, MAX_ARG_STR);

    switch (arg->type)
    {
    case A_NONE:

        snprintf(arg_str, MAX_ARG_STR - 1, "");
        break;

    case A_REG:
    case A_TEMP:

        snprintf(arg_str, MAX_ARG_STR - 1, "%s:%d", arg->name, arg_size[arg->size]);
        break;

    case A_CONST:

        snprintf(arg_str, MAX_ARG_STR - 1, "%llx:%d", arg->val, arg_size[arg->size]);
        break;
    }

    return arg_str;
}

void inst_print(reil_inst_t *inst)
{
    char arg_str[MAX_ARG_STR];

    // print address and mnemonic
    printf(
        "%.8llx.%.2x %7s ",
        inst->raw_info.addr, inst->inum, inst_op[inst->op]
    );

    // print instruction arguments
    printf("%16s, ", arg_print(&inst->a, arg_str));
    printf("%16s, ", arg_print(&inst->b, arg_str));
    printf("%16s  ", arg_print(&inst->c, arg_str));

    printf("\n");
}

int inst_handler(reil_inst_t *inst, void *context)
{
    // increment IR instruction counter
    *(int *)context += 1;

    // print IR instruction to the stdout
    inst_print(inst);

    return 0;
}

int translate_inst(reil_arch_t arch, unsigned char *data, int len)
{
    int translated = 0;

    // initialize REIL translator
    reil_t reil = reil_init(arch, inst_handler, (void *)&translated);
    if (reil)
    {
        // translate single instruction to REIL
        reil_translate(reil, 0, data, len);
        reil_close(reil);
        return translated;
    }

    return -1;
}

int main(int argc, char *argv[])
{
    unsigned char test_data[16] = {0x38,0xC2}; // xor eax, eax
    int len = 2;

    if (translate_inst(ARCH_X86, test_data, len) >= 0)
    {
        return 0;
    }

    return -1;
}
