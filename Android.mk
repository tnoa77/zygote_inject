LOCAL_PATH := $(call my-dir)
 
include $(CLEAR_VARS)
 
LOCAL_LDLIBS    := -llog
 
LOCAL_MODULE    := zygote_inject
LOCAL_SRC_FILES := zygote_inject.c

LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE
 
include $(BUILD_EXECUTABLE)