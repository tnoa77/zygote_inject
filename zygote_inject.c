#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <asm-generic/mman-common.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <dlfcn.h>
#include <dirent.h>
#include <android/log.h>

#include "zygote_inject.h"

int main(int argc, char **argv) {
	pid_t zygote_pid = zygote_find_pid();
	if (zygote_pid == -1) {
		LOGE("find zygote pid failed.");
		return -1;
	}
	LOGI("zygote_pid: %d", zygote_pid);
	ptrace_zygote(zygote_pid);

//	char data[100];
//	gets(data);
	return 0;
}

pid_t zygote_find_pid() {
	FILE *fp;
	DIR* dir;
	struct dirent * ptr;
	char filename[128];
	char buf[512];

	if ((dir = opendir("/proc")) == NULL) {
		LOGE("open file %s failed.", "/proc");
		return -1;
	}

	LOGI("finding zygote pid...");
	while ((ptr = readdir(dir)) != NULL) {
		if (ptr->d_type == DT_DIR) {
			snprintf(filename, sizeof(filename), "/proc/%s/cmdline",
					ptr->d_name);

			fp = fopen(filename, "r");
			if (!fp)
				continue;
			fgets(buf, sizeof(buf), fp);
			fclose(fp);

			if (strcmp("zygote", buf) == 0)
				return strtoul(ptr->d_name, NULL, 10);
		}
	}
	closedir(dir);
	return -1;
}

pid_t ptrace_zygote(pid_t zygote_pid) {
	int status;
	void *remote_mmap, *remote_dlopen, *remote_dlsym, *remote_dlclose,
			*remote_dlerror;

	if (ptrace(PTRACE_ATTACH, zygote_pid, NULL, NULL)) {
		LOGE("ptrace attach failed.");
	}

	int pid = waitpid(-1, &status, __WALL | WUNTRACED);
	if (pid == -1) {
		ptrace(PTRACE_DETACH, zygote_pid, NULL, NULL);
		LOGE("ptrace attach waitpid failed.");
		return -1;
	}

	struct pt_regs orig_regs, regs;
	ptrace(PTRACE_GETREGS, zygote_pid, NULL, orig_regs);
	memcpy(&regs, &orig_regs, sizeof(struct pt_regs));
	print_regs(&orig_regs);

	remote_mmap = get_remote_addr(zygote_pid, LIBC_PATH, (void*) mmap);
	if (remote_mmap == 0) {
		ptrace(PTRACE_DETACH, zygote_pid, NULL, NULL);
		return -1;
	}
	remote_dlopen = get_remote_addr(zygote_pid, LINKER_PATH, (void*) dlopen);
	if (remote_dlopen == 0) {
		ptrace(PTRACE_DETACH, zygote_pid, NULL, NULL);
		return -1;
	}
	remote_dlsym = get_remote_addr(zygote_pid, LINKER_PATH, (void*) dlsym);
	if (remote_dlsym == 0) {
		ptrace(PTRACE_DETACH, zygote_pid, NULL, NULL);
		return -1;
	}
	remote_dlclose = get_remote_addr(zygote_pid, LINKER_PATH, (void*) dlclose);
	if (remote_dlclose == 0) {
		ptrace(PTRACE_DETACH, zygote_pid, NULL, NULL);
		return -1;
	}
	remote_dlerror = get_remote_addr(zygote_pid, LINKER_PATH, (void*) dlerror);
	if (remote_dlerror == 0) {
		ptrace(PTRACE_DETACH, zygote_pid, NULL, NULL);
		return -1;
	}

	long parameters[10];
	/* call mmap */
	parameters[0] = 0;  // addr
	parameters[1] = 0x4000; // size
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
	parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags
	parameters[4] = 0; //fd
	parameters[5] = 0; //offset

	if (ptrace_call(pid, "mmap", remote_mmap, parameters, 6, &regs) == -1) {
		return ptrace_call_error(pid, "mmap");
	}

	LOGI("remote_mmap addr: [%08x]", (uint32_t )remote_mmap);
	LOGI("remote_dlopen addr: [%08x]", (uint32_t )remote_dlopen);
	LOGI("remote_dlsym addr: [%08x]", (uint32_t )remote_dlsym);
	LOGI("remote_dlclose addr: [%08x]", (uint32_t )remote_dlclose);
	LOGI("remote_dlerror addr: [%08x]", (uint32_t )remote_dlerror);

	LOGI("ptrace attach succeed.");
	ptrace(PTRACE_DETACH, zygote_pid, NULL, NULL);
	return 0;
}

void* get_module_base(pid_t pid, const char* module_name) {
	FILE* fp;
	uint32_t addr = 0;
	char* pch;
	char filename[128], line[1024];
	if (pid < 0)
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	else
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if (!fp) {
		LOGE("open file %s failed.", filename);
		return 0;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, module_name)) {
			pch = strtok(line, "-");
			addr = strtoul(pch, NULL, 16);
			break;
		}
	}
	fclose(fp);
	return (void *) addr;
}

void* get_remote_addr(pid_t pid, const char* module_name, void* local_addr) {
	void* local_handle = get_module_base(-1, module_name);
	void* remote_handle = get_module_base(pid, module_name);
	if (local_handle == 0) {
		LOGE("get local module %s address failed.", module_name);
		return 0;
	}
	if (remote_handle == 0) {
		LOGE("get remote module %s address failed.", module_name);
		return 0;
	}
	void* addr = (void*) ((uint32_t) remote_handle + (uint32_t) local_addr
			- (uint32_t) local_handle);
	LOGI("%s addr: local[%08x], remote[%08x]", module_name,
			(uint32_t )local_handle, (uint32_t )remote_handle);
	return addr;
}

int ptrace_call(pid_t pid, const char* func_name, void* func_addr, long* params,
		int param_num, struct pt_regs* regs) {
	LOGI("calling %s in target process.", func_name);
	int i;
	for (i = 0; i < 4 && i < param_num; ++i) {
		regs->uregs[i] = params[i];
	}
	if (i < param_num) {
		regs->ARM_sp-= (param_num-i) * sizeof(long);
		if(ptrace_writedata(pid, (void* )regs->ARM_sp, (uint8_t*)&params[i], (param_num - 1)*sizeof(long))) {
			LOGE("prtace write data failed.");
			return -1;
		}
	}
	regs->ARM_pc= (long)func_addr;
	if (regs->ARM_pc& 1) {  // thumb
		regs->ARM_pc &= (~1u);
		regs->ARM_cpsr |= CPSR_T_MASK;
	} else {  // arm
		regs->ARM_cpsr &= ~CPSR_T_MASK;
	}
	// set LR = 0 to generate SIGSEGV signal after the func return
	regs->ARM_lr= 0;

	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
		LOGE("prtace setregs failed.");
		return -1;
	}

	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		LOGE("prtace continue failed(0).");
		return -1;
	}

	int status = 0;
	waitpid(pid, &status, __WALL | WUNTRACED);
	while (status != 0xb7f) {
		if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
			LOGE("prtace continue failed(1).");
			return -1;
		}
		waitpid(pid, &status, __WALL | WUNTRACED);
	}
	return 0;
}

int ptrace_writedata(pid_t pid, uint8_t* dest, uint8_t* data, size_t size) {
	int group, remain;
	uint8_t* pos;
	union u {
		long val;
		char chars[sizeof(long)];
	} d;
	group = size / 4;
	remain = size % 4;

	pos = data;
	for (int i = 0; i < group; ++i) {
		memcpy(d.chars, pos, 4);
		if (ptrace(PTRACE_POKETEXT, pid, dest, d.val)) {
			LOGE("write memory addr 0x%x error.", (unsigned int)dest);
			return -1;
		}
		dest += 4;
		pos += 4;
	}

	if (remain > 0) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
		for (int i = 0; i < remain; ++i) {
			d.chars[i] = *pos++;
		}
		if (ptrace(PTRACE_POKETEXT, pid, dest, d.val)) {
			LOGE("write memory addr 0x%x error.", (unsigned int)dest);
			return -1;
		}
	}
	return 0;
}

int ptrace_call_error(pid_t pid, const char* func_name) {
	LOGE("ptrace call %s error", func_name);
	return -1;
}

void print_regs(struct pt_regs* regs) {
	for (int i = 0; i < 18; ++i)
		LOGI("%s:\t%016lx", reg_name[i], regs->uregs[i]);
}
