/*
 * zygote_inject.h
 *
 *  Created on: 2018年8月13日
 *      Author: thanoszhang
 */

#ifndef ZYGOTE_INJECT_H_
#define ZYGOTE_INJECT_H_

#define ARM_cpsr uregs[16]
#define ARM_pc uregs[15]
#define ARM_lr uregs[14]
#define ARM_sp uregs[13]
#define ARM_ip uregs[12]
#define ARM_fp uregs[11]
#define ARM_r10 uregs[10]
#define ARM_r9 uregs[9]
#define ARM_r8 uregs[8]
#define ARM_r7 uregs[7]
#define ARM_r6 uregs[6]
#define ARM_r5 uregs[5]
#define ARM_r4 uregs[4]
#define ARM_r3 uregs[3]
#define ARM_r2 uregs[2]
#define ARM_r1 uregs[1]
#define ARM_r0 uregs[0]
#define ARM_ORIG_r0 uregs[17]

const char* reg_name[] = { "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8",
		"R9", "R10", "FP", "IP", "SP", "LR", "PC", "CPSR", "PRIG_R0" };

#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, "ZygoteInject", __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG , "ZygoteInject", __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO  , "ZygoteInject", __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN  , "ZygoteInject", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR  , "ZygoteInject", __VA_ARGS__)

#define LIBC_PATH		"libc.so"
#define LINKER_PATH		"/system/bin/linker"
#define CPSR_T_MASK		(1u < 5)

pid_t zygote_find_pid();
pid_t ptrace_zygote(pid_t);
void print_regs(struct pt_regs*);
void* get_module_base(pid_t, const char*);
void* get_remote_addr(pid_t, const char*, void*);
int ptrace_call(pid_t, const char*, void*, long*, int, struct pt_regs*);
int ptrace_writedata(pid_t, uint8_t*, uint8_t*, size_t);
int ptrace_call_error(pid_t, const char*);

#endif /* ZYGOTE_INJECT_H_ */
