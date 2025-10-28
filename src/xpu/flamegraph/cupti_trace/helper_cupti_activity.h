/**
 * Copyright 2022-2024 NVIDIA Corporation.  All rights reserved.
 *
 * Please refer to the NVIDIA end user license agreement (EULA) associated
 * with this source code for terms and conditions that govern your use of
 * this software. Any use, reproduction, disclosure, or distribution of
 * this software and related documentation outside the terms of the EULA
 * is strictly prohibited.
 *
 */

////////////////////////////////////////////////////////////////////////////////

#ifndef HELPER_CUPTI_ACTIVITY_H_
#define HELPER_CUPTI_ACTIVITY_H_

#pragma once

// System headers
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// CUPTI headers
#include <cupti.h>
#include <helper_cupti.h>
#include <unordered_map>
#include <unordered_set>
#include <list>


// Macros
#define LINE_SIZE 2048

// CUPTI buffer size 32 MB
#define BUF_SIZE (32 * 1024 * 1024)

// 8-byte alignment for the buffers
#define ALIGN_SIZE (8)
#define ALIGN_BUFFER(buffer, align)                                                 \
  (((uintptr_t) (buffer) & ((align)-1)) ? ((buffer) + (align) - ((uintptr_t) (buffer) & ((align)-1))) : (buffer))

typedef uint64_t HashMapKey;

// Data structures

// Global state
typedef struct GlobalState_st
{
    CUpti_SubscriberHandle subscriberHandle;                         // CUPTI subcriber handle to subcribe to CUPTI callbacks.
    size_t activityBufferSize;                                       // CUPTI activity buffer size.
    FILE   *pOutputFile;                                             // File handle to print the CUPTI activity records. default = stdout.
    void   *pUserData;                                               // User data used to initialize CUPTI trace. Refer UserData structure.
    uint64_t buffersRequested;                                       // Requested buffers by CUPTI.
    uint64_t buffersCompleted;                                       // Completed buffers by received from CUPTI.
} GlobalState;

// User data provided by the application using InitCuptiTrace()
// User need to allocate memory for this structure in the sample.
// Set the options according to the workloads requirement.
typedef struct UserData_st
{
    size_t  activityBufferSize;                                      // CUPTI activity buffer size.
    size_t  deviceBufferSize;                                        // CUPTI device buffer size.
    uint8_t flushAtStreamSync;                                       // Flush CUPTI activity records at stream syncronization.
    uint8_t flushAtCtxSync;                                          // Flush CUPTI activity records at context syncronization.
    uint8_t printCallbacks;                                          // Print callbacks enabled in CUPTI.
    uint8_t printActivityRecords;                                    // Print CUPTI activity records.
    uint8_t skipCuptiSubscription;                                   // Check if the user application wants to skip subscription in CUPTI.
    void    (*pPostProcessActivityRecords)(CUpti_Activity *pRecord); // Provide function pointer in the user application for CUPTI records for post processing.
} UserData;

// Global variables
static GlobalState globals = { 0 };

// Helper Functions
static const char *
GetActivityKindString(
    CUpti_ActivityKind activityKind)
{
    switch (activityKind)
    {
        case CUPTI_ACTIVITY_KIND_MEMCPY:
            return "MEMCPY";
        case CUPTI_ACTIVITY_KIND_MEMSET:
            return "MEMSET";
        case CUPTI_ACTIVITY_KIND_KERNEL:
            return "KERNEL";
        case CUPTI_ACTIVITY_KIND_DRIVER:
            return "DRIVER";
        case CUPTI_ACTIVITY_KIND_RUNTIME:
            return "RUNTIME";
        case CUPTI_ACTIVITY_KIND_DEVICE:
            return "DEVICE";
        case CUPTI_ACTIVITY_KIND_CONTEXT:
            return "CONTEXT";
        case CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL:
            return "CONCURRENT_KERNEL";
        case CUPTI_ACTIVITY_KIND_NAME:
            return "NAME";
        case CUPTI_ACTIVITY_KIND_MARKER:
            return "MARKER";
        case CUPTI_ACTIVITY_KIND_MARKER_DATA:
            return "MARKER_DATA";
        case CUPTI_ACTIVITY_KIND_SOURCE_LOCATOR:
            return "SOURCE_LOCATOR";
        case CUPTI_ACTIVITY_KIND_GLOBAL_ACCESS:
            return "GLOBAL_ACCESS";
        case CUPTI_ACTIVITY_KIND_BRANCH:
            return "BRANCH";
        case CUPTI_ACTIVITY_KIND_OVERHEAD:
            return "OVERHEAD";
        case CUPTI_ACTIVITY_KIND_CDP_KERNEL:
            return "CDP_KERNEL";
        case CUPTI_ACTIVITY_KIND_PREEMPTION:
            return "PREEMPTION";
        case CUPTI_ACTIVITY_KIND_ENVIRONMENT:
            return "ENVIRONMENT";
        case CUPTI_ACTIVITY_KIND_MEMCPY2:
            return "MEMCPY2";
        case CUPTI_ACTIVITY_KIND_INSTRUCTION_EXECUTION:
            return "INSTRUCTION_EXECUTION";
        case CUPTI_ACTIVITY_KIND_UNIFIED_MEMORY_COUNTER:
            return "UNIFIED_MEMORY_COUNTER";
        case CUPTI_ACTIVITY_KIND_FUNCTION:
            return "FUNCTION";
        case CUPTI_ACTIVITY_KIND_MODULE:
            return "MODULE";
        case CUPTI_ACTIVITY_KIND_DEVICE_ATTRIBUTE:
            return "DEVICE_ATTRIBUTE";
        case CUPTI_ACTIVITY_KIND_SHARED_ACCESS:
            return "SHARED_ACCESS";
        case CUPTI_ACTIVITY_KIND_PC_SAMPLING:
            return "PC_SAMPLING";
        case CUPTI_ACTIVITY_KIND_PC_SAMPLING_RECORD_INFO:
            return "PC_SAMPLING_RECORD_INFO";
        case CUPTI_ACTIVITY_KIND_INSTRUCTION_CORRELATION:
            return "INSTRUCTION_CORRELATION";
        case CUPTI_ACTIVITY_KIND_OPENACC_DATA:
            return "OPENACC_DATA";
        case CUPTI_ACTIVITY_KIND_OPENACC_LAUNCH:
            return "OPENACC_LAUNCH";
        case CUPTI_ACTIVITY_KIND_OPENACC_OTHER:
            return "OPENACC_OTHER";
        case CUPTI_ACTIVITY_KIND_CUDA_EVENT:
            return "CUDA_EVENT";
        case CUPTI_ACTIVITY_KIND_STREAM:
            return "STREAM";
        case CUPTI_ACTIVITY_KIND_SYNCHRONIZATION:
            return "SYNCHRONIZATION";
        case CUPTI_ACTIVITY_KIND_EXTERNAL_CORRELATION:
            return "EXTERNAL_CORRELATION";
        case CUPTI_ACTIVITY_KIND_NVLINK:
            return "NVLINK";
        case CUPTI_ACTIVITY_KIND_MEMORY:
            return "MEMORY";
        case CUPTI_ACTIVITY_KIND_PCIE:
            return "PCIE";
        case CUPTI_ACTIVITY_KIND_OPENMP:
            return "OPENMP";
        case CUPTI_ACTIVITY_KIND_INTERNAL_LAUNCH_API:
            return "INTERNAL_LAUNCH_API";
        case CUPTI_ACTIVITY_KIND_MEMORY2:
            return "MEMORY2";
        case CUPTI_ACTIVITY_KIND_MEMORY_POOL:
            return "MEMORY_POOL";
        case CUPTI_ACTIVITY_KIND_GRAPH_TRACE:
            return "GRAPH_TRACE";
        case CUPTI_ACTIVITY_KIND_JIT:
            return "JIT";
        case CUPTI_ACTIVITY_KIND_MEM_DECOMPRESS:
            return "MEM_DECOMPRESS";
        default:
            return "<unknown>";
    }
}

static CUpti_ActivityKind
GetActivityKindFromString(
    const char *pActivityKindString)
{
    if (!pActivityKindString)
    {
        std::cerr << "\n\nError: NULL string.\n\n";
        exit(-1);
    }

    if (!stricmp(pActivityKindString, "MEMCPY"))
    {
        return CUPTI_ACTIVITY_KIND_MEMCPY;
    }
    else if (!stricmp(pActivityKindString, "MEMSET"))
    {
        return CUPTI_ACTIVITY_KIND_MEMSET;
    }
    else if (!stricmp(pActivityKindString, "KERNEL"))
    {
        return CUPTI_ACTIVITY_KIND_KERNEL;
    }
    else if (!stricmp(pActivityKindString, "DRIVER"))
    {
        return CUPTI_ACTIVITY_KIND_DRIVER;
    }
    else if (!stricmp(pActivityKindString, "RUNTIME"))
    {
        return CUPTI_ACTIVITY_KIND_RUNTIME;
    }
    else if (!stricmp(pActivityKindString, "DEVICE"))
    {
        return CUPTI_ACTIVITY_KIND_DEVICE;
    }
    else if (!stricmp(pActivityKindString, "CONTEXT"))
    {
        return CUPTI_ACTIVITY_KIND_CONTEXT;
    }
    else if (!stricmp(pActivityKindString, "CONCURRENT_KERNEL"))
    {
        return CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL;
    }
    else if (!stricmp(pActivityKindString, "NAME"))
    {
        return CUPTI_ACTIVITY_KIND_NAME;
    }
    else if (!stricmp(pActivityKindString, "MARKER"))
    {
        return CUPTI_ACTIVITY_KIND_MARKER;
    }
    else if (!stricmp(pActivityKindString, "MARKER_DATA"))
    {
        return CUPTI_ACTIVITY_KIND_MARKER_DATA;
    }
    else if (!stricmp(pActivityKindString, "SOURCE_LOCATOR"))
    {
        return CUPTI_ACTIVITY_KIND_SOURCE_LOCATOR;
    }
    else if (!stricmp(pActivityKindString, "GLOBAL_ACCESS"))
    {
        return CUPTI_ACTIVITY_KIND_GLOBAL_ACCESS;
    }
    else if (!stricmp(pActivityKindString, "BRANCH"))
    {
        return CUPTI_ACTIVITY_KIND_BRANCH;
    }
    else if (!stricmp(pActivityKindString, "OVERHEAD"))
    {
        return CUPTI_ACTIVITY_KIND_OVERHEAD;
    }
    else if (!stricmp(pActivityKindString, "CDP_KERNEL"))
    {
        return CUPTI_ACTIVITY_KIND_CDP_KERNEL;
    }
    else if (!stricmp(pActivityKindString, "PREEMPTION"))
    {
        return CUPTI_ACTIVITY_KIND_PREEMPTION;
    }
    else if (!stricmp(pActivityKindString, "ENVIRONMENT"))
    {
        return CUPTI_ACTIVITY_KIND_ENVIRONMENT;
    }
    else if (!stricmp(pActivityKindString, "MEMCPY2"))
    {
        return CUPTI_ACTIVITY_KIND_MEMCPY2;
    }
    else if (!stricmp(pActivityKindString, "INSTRUCTION_EXECUTION"))
    {
        return CUPTI_ACTIVITY_KIND_INSTRUCTION_EXECUTION;
    }
    else if (!stricmp(pActivityKindString, "UNIFIED_MEMORY_COUNTER"))
    {
        return CUPTI_ACTIVITY_KIND_UNIFIED_MEMORY_COUNTER;
    }
    else if (!stricmp(pActivityKindString, "FUNCTION"))
    {
        return CUPTI_ACTIVITY_KIND_FUNCTION;
    }
    else if (!stricmp(pActivityKindString, "MODULE"))
    {
        return CUPTI_ACTIVITY_KIND_MODULE;
    }
    else if (!stricmp(pActivityKindString, "DEVICE_ATTRIBUTE"))
    {
        return CUPTI_ACTIVITY_KIND_DEVICE_ATTRIBUTE;
    }
    else if (!stricmp(pActivityKindString, "SHARED_ACCESS"))
    {
        return CUPTI_ACTIVITY_KIND_SHARED_ACCESS;
    }
    else if (!stricmp(pActivityKindString, "PC_SAMPLING"))
    {
        return CUPTI_ACTIVITY_KIND_PC_SAMPLING;
    }
    else if (!stricmp(pActivityKindString, "PC_SAMPLING_RECORD_INFO"))
    {
        return CUPTI_ACTIVITY_KIND_PC_SAMPLING_RECORD_INFO;
    }
    else if (!stricmp(pActivityKindString, "INSTRUCTION_CORRELATION"))
    {
        return CUPTI_ACTIVITY_KIND_INSTRUCTION_CORRELATION;
    }
    else if (!stricmp(pActivityKindString, "OPENACC_DATA"))
    {
        return CUPTI_ACTIVITY_KIND_OPENACC_DATA;
    }
    else if (!stricmp(pActivityKindString, "OPENACC_LAUNCH"))
    {
        return CUPTI_ACTIVITY_KIND_OPENACC_LAUNCH;
    }
    else if (!stricmp(pActivityKindString, "OPENACC_OTHER"))
    {
        return CUPTI_ACTIVITY_KIND_OPENACC_OTHER;
    }
    else if (!stricmp(pActivityKindString, "CUDA_EVENT"))
    {
        return CUPTI_ACTIVITY_KIND_CUDA_EVENT;
    }
    else if (!stricmp(pActivityKindString, "STREAM"))
    {
        return CUPTI_ACTIVITY_KIND_STREAM;
    }
    else if (!stricmp(pActivityKindString, "SYNCHRONIZATION"))
    {
        return CUPTI_ACTIVITY_KIND_SYNCHRONIZATION;
    }
    else if (!stricmp(pActivityKindString, "EXTERNAL_CORRELATION"))
    {
        return CUPTI_ACTIVITY_KIND_EXTERNAL_CORRELATION;
    }
    else if (!stricmp(pActivityKindString, "NVLINK"))
    {
        return CUPTI_ACTIVITY_KIND_NVLINK;
    }
    else if (!stricmp(pActivityKindString, "MEMORY"))
    {
        return CUPTI_ACTIVITY_KIND_MEMORY;
    }
    else if (!stricmp(pActivityKindString, "PCIE"))
    {
        return CUPTI_ACTIVITY_KIND_PCIE;
    }
    else if (!stricmp(pActivityKindString, "OPENMP"))
    {
        return CUPTI_ACTIVITY_KIND_OPENMP;
    }
    else if (!stricmp(pActivityKindString, "INTERNAL_LAUNCH_API"))
    {
        return CUPTI_ACTIVITY_KIND_INTERNAL_LAUNCH_API;
    }
    else if (!stricmp(pActivityKindString, "MEMORY2"))
    {
        return CUPTI_ACTIVITY_KIND_MEMORY2;
    }
    else if (!stricmp(pActivityKindString, "MEMORY_POOL"))
    {
        return CUPTI_ACTIVITY_KIND_MEMORY_POOL;
    }
    else if (!stricmp(pActivityKindString, "GRAPH_TRACE"))
    {
        return CUPTI_ACTIVITY_KIND_GRAPH_TRACE;
    }
    else if (!stricmp(pActivityKindString, "JIT"))
    {
        return CUPTI_ACTIVITY_KIND_JIT;
    }
else if (!stricmp(pActivityKindString, "MEM_DECOMPRESS"))
    {
        return CUPTI_ACTIVITY_KIND_MEM_DECOMPRESS;
    }
    else {
        std::cerr << "\n\nError: Invalid string " << pActivityKindString << " cannot be converted to CUPTI Activity Kind.\n\n";
        exit(-1);
    }
}



static const char *
GetActivityObjectKindString(
    CUpti_ActivityObjectKind objectKind)
{
    switch (objectKind)
    {
        case CUPTI_ACTIVITY_OBJECT_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_ACTIVITY_OBJECT_PROCESS:
            return "PROCESS";
        case CUPTI_ACTIVITY_OBJECT_THREAD:
            return "THREAD";
        case CUPTI_ACTIVITY_OBJECT_DEVICE:
            return "DEVICE";
        case CUPTI_ACTIVITY_OBJECT_CONTEXT:
            return "CONTEXT";
        case CUPTI_ACTIVITY_OBJECT_STREAM:
            return "STREAM";
        default:
            return "<unknown>";
    }
}

static uint32_t
GetActivityObjectKindId(
    CUpti_ActivityObjectKind objectKind,
    CUpti_ActivityObjectKindId *pObjectKindId)
{
    switch (objectKind)
    {
        case CUPTI_ACTIVITY_OBJECT_UNKNOWN:
            return 0xffffffff;
        case CUPTI_ACTIVITY_OBJECT_PROCESS:
            return pObjectKindId->pt.processId;
        case CUPTI_ACTIVITY_OBJECT_THREAD:
            return pObjectKindId->pt.threadId;
        case CUPTI_ACTIVITY_OBJECT_DEVICE:
            return pObjectKindId->dcs.deviceId;
        case CUPTI_ACTIVITY_OBJECT_CONTEXT:
            return pObjectKindId->dcs.contextId;
        case CUPTI_ACTIVITY_OBJECT_STREAM:
            return pObjectKindId->dcs.streamId;
        default:
            return 0xffffffff;
    }
}

static const char *
GetActivityOverheadKindString(
    CUpti_ActivityOverheadKind overheadKind)
{
    switch (overheadKind)
    {
        case CUPTI_ACTIVITY_OVERHEAD_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_ACTIVITY_OVERHEAD_DRIVER_COMPILER:
            return "DRIVER_COMPILER";
        case CUPTI_ACTIVITY_OVERHEAD_CUPTI_BUFFER_FLUSH:
            return "CUPTI_BUFFER_FLUSH";
        case CUPTI_ACTIVITY_OVERHEAD_CUPTI_INSTRUMENTATION:
            return "CUPTI_INSTRUMENTATION";
        case CUPTI_ACTIVITY_OVERHEAD_CUPTI_RESOURCE:
            return "CUPTI_RESOURCE";
        case CUPTI_ACTIVITY_OVERHEAD_RUNTIME_TRIGGERED_MODULE_LOADING:
            return "RUNTIME_TRIGGERED_MODULE_LOADING";
        case CUPTI_ACTIVITY_OVERHEAD_LAZY_FUNCTION_LOADING:
            return "LAZY_FUNCTION_LOADING";
        case CUPTI_ACTIVITY_OVERHEAD_COMMAND_BUFFER_FULL:
            return "COMMAND_BUFFER_FULL";
        case CUPTI_ACTIVITY_OVERHEAD_ACTIVITY_BUFFER_REQUEST:
            return "ACTIVITY_BUFFER_REQUEST";
        case CUPTI_ACTIVITY_OVERHEAD_UVM_ACTIVITY_INIT:
            return "UVM_ACTIVITY_INIT";
        default:
            return "<unknown>";
    }
}

static const char *
GetComputeApiKindString(
    CUpti_ActivityComputeApiKind computeApiKind)
{
    switch (computeApiKind)
    {
        case CUPTI_ACTIVITY_COMPUTE_API_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_ACTIVITY_COMPUTE_API_CUDA:
            return "CUDA";
        case CUPTI_ACTIVITY_COMPUTE_API_CUDA_MPS:
            return "CUDA_MPS";
        default:
            return "<unknown>";
    }
}

static const char *
GetStallReasonString(
    CUpti_ActivityPCSamplingStallReason pcSamplingStallReason)
{
    switch (pcSamplingStallReason)
    {
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_INVALID:
            return "INVALID";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_NONE:
            return "NONE";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_INST_FETCH:
            return "INSTRUCTION_FETCH";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_EXEC_DEPENDENCY:
            return "EXECUTION_DEPENDENCY";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_MEMORY_DEPENDENCY:
            return "MEMORY_DEPENDENCY";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_TEXTURE:
            return "TEXTURE";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_SYNC:
            return "SYNC";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_CONSTANT_MEMORY_DEPENDENCY:
            return "CONSTANT_MEMORY_DEPENDENCY";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_PIPE_BUSY:
            return "PIPE_BUSY";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_MEMORY_THROTTLE:
            return "MEMORY_THROTTLE";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_NOT_SELECTED:
            return "SELECTED";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_OTHER:
            return "OTHER";
        case CUPTI_ACTIVITY_PC_SAMPLING_STALL_SLEEPING:
            return "SLEEPING";
        default:
            return "<unknown>";
    }
}

static const char *
GetMemcpyKindString(
    CUpti_ActivityMemcpyKind memcpyKind)
{
    switch (memcpyKind)
    {
        case CUPTI_ACTIVITY_MEMCPY_KIND_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_ACTIVITY_MEMCPY_KIND_HTOD:
            return "HtoD";
        case CUPTI_ACTIVITY_MEMCPY_KIND_DTOH:
            return "DtoH";
        case CUPTI_ACTIVITY_MEMCPY_KIND_HTOA:
            return "HtoA";
        case CUPTI_ACTIVITY_MEMCPY_KIND_ATOH:
            return "AtoH";
        case CUPTI_ACTIVITY_MEMCPY_KIND_ATOA:
            return "AtoA";
        case CUPTI_ACTIVITY_MEMCPY_KIND_ATOD:
            return "AtoD";
        case CUPTI_ACTIVITY_MEMCPY_KIND_DTOA:
            return "DtoA";
        case CUPTI_ACTIVITY_MEMCPY_KIND_DTOD:
            return "DtoD";
        case CUPTI_ACTIVITY_MEMCPY_KIND_HTOH:
            return "HtoH";
        case CUPTI_ACTIVITY_MEMCPY_KIND_PTOP:
            return "PtoP";
        default:
            return "<unknown>";
    }
}

static const char *
GetMemoryKindString(
    CUpti_ActivityMemoryKind memoryKind)
{
    switch (memoryKind)
    {
        case CUPTI_ACTIVITY_MEMORY_KIND_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_ACTIVITY_MEMORY_KIND_PAGEABLE:
            return "PAGEABLE";
        case CUPTI_ACTIVITY_MEMORY_KIND_PINNED:
            return "PINNED";
        case CUPTI_ACTIVITY_MEMORY_KIND_DEVICE:
            return "DEVICE";
        case CUPTI_ACTIVITY_MEMORY_KIND_ARRAY:
            return "ARRAY";
        case CUPTI_ACTIVITY_MEMORY_KIND_MANAGED:
            return "MANAGED";
        case CUPTI_ACTIVITY_MEMORY_KIND_DEVICE_STATIC:
            return "DEVICE_STATIC";
        case CUPTI_ACTIVITY_MEMORY_KIND_MANAGED_STATIC:
            return "MANAGED_STATIC";
        default:
            return "<unknown>";
    }
}

static const char *
GetPreemptionKindString(
    CUpti_ActivityPreemptionKind preemptionKind)
{
    switch (preemptionKind)
    {
        case CUPTI_ACTIVITY_PREEMPTION_KIND_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_ACTIVITY_PREEMPTION_KIND_SAVE:
            return "SAVE";
        case CUPTI_ACTIVITY_PREEMPTION_KIND_RESTORE:
            return "RESTORE";
        default:
            return "<unknown>";
    }
}

static const char *
GetActivityEnvironmentKindString(
    CUpti_ActivityEnvironmentKind environmentKind)
{
    switch (environmentKind)
    {
        case CUPTI_ACTIVITY_ENVIRONMENT_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_ACTIVITY_ENVIRONMENT_SPEED:
            return "SPEED";
        case CUPTI_ACTIVITY_ENVIRONMENT_TEMPERATURE:
            return "TEMPERATURE";
        case CUPTI_ACTIVITY_ENVIRONMENT_POWER:
            return "POWER";
        case CUPTI_ACTIVITY_ENVIRONMENT_COOLING:
            return "COOLING";
        default:
            return "<unknown>";
    }
}

static const char *
GetUvmCounterScopeString(
    CUpti_ActivityUnifiedMemoryCounterScope unifiedMemoryCounterScope)
{
    switch (unifiedMemoryCounterScope)
    {
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_SCOPE_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_SCOPE_PROCESS_SINGLE_DEVICE:
            return "PROCESS_SINGLE_DEVICE";
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_SCOPE_PROCESS_ALL_DEVICES:
            return "PROCESS_ALL_DEVICES";
        default:
            return "<unknown>";
    }
}

static const char *
GetUvmCounterKindString(
    CUpti_ActivityUnifiedMemoryCounterKind unifiedMemoryCounterKind)
{
    switch (unifiedMemoryCounterKind)
    {
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_KIND_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_KIND_BYTES_TRANSFER_HTOD:
            return "BYTES_TRANSFER_HTOD";
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_KIND_BYTES_TRANSFER_DTOH:
            return "BYTES_TRANSFER_DTOH";
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_KIND_CPU_PAGE_FAULT_COUNT:
            return "CPU_PAGE_FAULT_COUNT";
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_KIND_GPU_PAGE_FAULT:
            return "GPU_PAGE_FAULT";
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_KIND_THRASHING:
            return "THRASHING";
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_KIND_THROTTLING:
            return "THROTTLING";
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_KIND_REMOTE_MAP:
            return "REMOTE_MAP";
        case CUPTI_ACTIVITY_UNIFIED_MEMORY_COUNTER_KIND_BYTES_TRANSFER_DTOD:
            return "BYTES_TRANSFER_DTOD";
        default:
            return "<unknown>";
    }
}

static const char *
GetSynchronizationType(
    CUpti_ActivitySynchronizationType syncronizationType)
{
    switch (syncronizationType)
    {
        case CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_EVENT_SYNCHRONIZE:
            return "EVENT_SYNCHRONIZE";
        case CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_STREAM_WAIT_EVENT:
            return "STREAM_WAIT_EVENT";
        case CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_STREAM_SYNCHRONIZE:
            return "STREAM_SYNCHRONIZE";
        case CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_CONTEXT_SYNCHRONIZE:
            return "CONTEXT_SYNCHRONIZE";
        default:
            return "<unknown>";
    }
}

static const char *
GetStreamType(
    CUpti_ActivityStreamFlag streamFlag)
{
    switch (streamFlag)
    {
        case CUPTI_ACTIVITY_STREAM_CREATE_FLAG_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_ACTIVITY_STREAM_CREATE_FLAG_DEFAULT:
            return "DEFAULT_STREAM";
        case CUPTI_ACTIVITY_STREAM_CREATE_FLAG_NON_BLOCKING:
            return "NON_BLOCKING_STREAM";
        case CUPTI_ACTIVITY_STREAM_CREATE_FLAG_NULL:
            return "NULL_STREAM";
        default:
            return "<unknown>";
    }
}

static const char *
GetMemoryOperationTypeString(
    CUpti_ActivityMemoryOperationType memoryOperationType)
{
    switch (memoryOperationType)
    {
        case CUPTI_ACTIVITY_MEMORY_OPERATION_TYPE_INVALID:
            return "INVALID";
        case CUPTI_ACTIVITY_MEMORY_OPERATION_TYPE_ALLOCATION:
            return "ALLOCATE";
        case CUPTI_ACTIVITY_MEMORY_OPERATION_TYPE_RELEASE:
            return "RELEASE";
        default:
            return "<unknown>";
    }
}

static const char *
GetMemoryPoolTypeString(
    CUpti_ActivityMemoryPoolType memoryPoolType)
{
    switch (memoryPoolType)
    {
        case CUPTI_ACTIVITY_MEMORY_POOL_TYPE_INVALID:
            return "INVALID";
        case CUPTI_ACTIVITY_MEMORY_POOL_TYPE_LOCAL:
            return "LOCAL";
        case CUPTI_ACTIVITY_MEMORY_POOL_TYPE_IMPORTED:
            return "IMPORTED";
        default:
            return "<unknown>";
    }
}

static const char *
GetMemoryPoolOperationTypeString(
    CUpti_ActivityMemoryPoolOperationType memoryPoolOperationType)
{
    switch (memoryPoolOperationType)
    {
        case CUPTI_ACTIVITY_MEMORY_POOL_OPERATION_TYPE_INVALID:
            return "INVALID";
        case CUPTI_ACTIVITY_MEMORY_POOL_OPERATION_TYPE_CREATED:
            return "MEM_POOL_CREATED";
        case CUPTI_ACTIVITY_MEMORY_POOL_OPERATION_TYPE_DESTROYED:
            return "MEM_POOL_DESTROYED";
        case CUPTI_ACTIVITY_MEMORY_POOL_OPERATION_TYPE_TRIMMED:
            return "MEM_POOL_TRIMMED";
        default:
            return "<unknown>";
    }
}

static const char *
GetChannelType(
    CUpti_ChannelType channelType)
{
    switch (channelType)
    {
        case CUPTI_CHANNEL_TYPE_INVALID:
            return "INVALID";
        case CUPTI_CHANNEL_TYPE_COMPUTE:
            return "COMPUTE";
        case CUPTI_CHANNEL_TYPE_ASYNC_MEMCPY:
           return "ASYNC_MEMCPY";
        case CUPTI_CHANNEL_TYPE_DECOMP:
            return "DECOMP";
        default:
            return "<unknown>";
    }
}

static const char *
GetJitEntryType(
    CUpti_ActivityJitEntryType jitEntryType)
{
    switch (jitEntryType)
    {
        case CUPTI_ACTIVITY_JIT_ENTRY_INVALID:
            return "INVALID";
        case CUPTI_ACTIVITY_JIT_ENTRY_PTX_TO_CUBIN:
            return "PTX_TO_CUBIN";
        case CUPTI_ACTIVITY_JIT_ENTRY_NVVM_IR_TO_PTX:
            return "NVVM_IR_TO_PTX";
        default:
            return "<unknown>";
    }
}

static const char *
GetJitOperationType(
    CUpti_ActivityJitOperationType jitOperationType)
{
    switch (jitOperationType)
    {
        case CUPTI_ACTIVITY_JIT_OPERATION_INVALID:
            return "INVALID";
        case CUPTI_ACTIVITY_JIT_OPERATION_CACHE_LOAD:
            return "CACHE_LOAD";
        case CUPTI_ACTIVITY_JIT_OPERATION_CACHE_STORE:
            return "CACHE_STORE";
        case CUPTI_ACTIVITY_JIT_OPERATION_COMPILE:
            return "COMPILE";
        default:
            return "<unknown>";
    }
}

static const char *
GetName(
    const char *pName)
{
    if (pName == NULL)
    {
        return "<null>";
    }

    return pName;
}

static const char *
GetDomainName(
    const char *pName)
{
    if (pName == NULL)
    {
        return "<default domain>";
    }

    return pName;
}

static const char *
GetOpenAccConstructString(
    CUpti_OpenAccConstructKind openAccConstructKind)
{
    switch (openAccConstructKind)
    {
        case CUPTI_OPENACC_CONSTRUCT_KIND_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_OPENACC_CONSTRUCT_KIND_PARALLEL:
            return "PARALLEL";
        case CUPTI_OPENACC_CONSTRUCT_KIND_KERNELS:
            return "KERNELS";
        case CUPTI_OPENACC_CONSTRUCT_KIND_LOOP:
            return "LOOP";
        case CUPTI_OPENACC_CONSTRUCT_KIND_DATA:
            return "DATA";
        case CUPTI_OPENACC_CONSTRUCT_KIND_ENTER_DATA:
            return "ENTER_DATA";
        case CUPTI_OPENACC_CONSTRUCT_KIND_EXIT_DATA:
            return "EXIT_DATA";
        case CUPTI_OPENACC_CONSTRUCT_KIND_HOST_DATA:
            return "HOST_DATA";
        case CUPTI_OPENACC_CONSTRUCT_KIND_ATOMIC:
            return "ATOMIC";
        case CUPTI_OPENACC_CONSTRUCT_KIND_DECLARE:
            return "DECLARE";
        case CUPTI_OPENACC_CONSTRUCT_KIND_INIT:
            return "INIT";
        case CUPTI_OPENACC_CONSTRUCT_KIND_SHUTDOWN:
            return "SHUTDOWN";
        case CUPTI_OPENACC_CONSTRUCT_KIND_SET:
            return "SET";
        case CUPTI_OPENACC_CONSTRUCT_KIND_UPDATE:
            return "UPDATE";
        case CUPTI_OPENACC_CONSTRUCT_KIND_ROUTINE:
            return "ROUTINE";
        case CUPTI_OPENACC_CONSTRUCT_KIND_WAIT:
            return "WAIT";
        case CUPTI_OPENACC_CONSTRUCT_KIND_RUNTIME_API:
            return "RUNTIME_API";
        default:
            return NULL;
    }
}

static const char *
GetExternalCorrelationKindString(
    CUpti_ExternalCorrelationKind externalCorrelationKind)
{
    switch (externalCorrelationKind)
    {
        case CUPTI_EXTERNAL_CORRELATION_KIND_INVALID:
            return "INVALID";
        case CUPTI_EXTERNAL_CORRELATION_KIND_UNKNOWN:
            return "UNKNOWN";
        case CUPTI_EXTERNAL_CORRELATION_KIND_OPENACC:
            return "OPENACC";
        case CUPTI_EXTERNAL_CORRELATION_KIND_CUSTOM0:
            return "CUSTOM0";
        case CUPTI_EXTERNAL_CORRELATION_KIND_CUSTOM1:
            return "CUSTOM1";
        case CUPTI_EXTERNAL_CORRELATION_KIND_CUSTOM2:
            return "CUSTOM2";
        default:
            return "<unknown>";
    }
}

static const char *
GetDevTypeNvlink(
    CUpti_DevType devType)
{
    switch (devType)
    {
        case CUPTI_DEV_TYPE_INVALID:
            return "INVALID";
        case CUPTI_DEV_TYPE_GPU:
            return "GPU";
        case CUPTI_DEV_TYPE_NPU:
            return "CPU";
        default:
            return "<unknown>";
    }
}

static uint32_t
GetCorrelationId(
    CUpti_Activity *pRecord)
{
    switch (pRecord->kind)
    {
        case CUPTI_ACTIVITY_KIND_MEMCPY:
            return ((CUpti_ActivityMemcpy6 *)pRecord)->correlationId;
        case CUPTI_ACTIVITY_KIND_MEMSET:
            return ((CUpti_ActivityMemset4 *)pRecord)->correlationId;
        case CUPTI_ACTIVITY_KIND_KERNEL:
        case CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL:
            return ((CUpti_ActivityKernel9 *)pRecord)->correlationId;
        case CUPTI_ACTIVITY_KIND_DRIVER:
        case CUPTI_ACTIVITY_KIND_RUNTIME:
            return ((CUpti_ActivityAPI *)pRecord)->correlationId;
        case CUPTI_ACTIVITY_KIND_CDP_KERNEL:
            return ((CUpti_ActivityCdpKernel *)pRecord)->correlationId;
        case CUPTI_ACTIVITY_KIND_MEMCPY2:
            return ((CUpti_ActivityMemcpyPtoP4 *)pRecord)->correlationId;
        default:
            return 0;
    }
}

static void
PrintOpenaccCommon(
    FILE *pFileHandle,
    CUpti_ActivityOpenAcc *pOpenAcc)
{
    fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, eventKind %u, parentConstruct %s, version %u, implicit %u, deviceType %u, deviceNumber %u, threadId %u,\n"
            "  async %llu, asyncMap %llu, lineNo %u, endLineNo %u, funcLineNo %u, endFuncLineNo %u,\n"
            "  cuDeviceId %u, cuContextId %u, cuStreamId %u, cuProcessId %u, cuThreadId %u, externalId %llu",
            GetActivityKindString(pOpenAcc->kind),
            (unsigned long long)pOpenAcc->start,
            (unsigned long long)pOpenAcc->end,
            (unsigned long long)(pOpenAcc->end - pOpenAcc->start),
            pOpenAcc->eventKind,
            GetOpenAccConstructString((CUpti_OpenAccConstructKind)pOpenAcc->parentConstruct),
            pOpenAcc->version,
            pOpenAcc->implicit,
            pOpenAcc->deviceType,
            pOpenAcc->deviceNumber,
            pOpenAcc->threadId,
            (unsigned long long)pOpenAcc->async,
            (unsigned long long)pOpenAcc->asyncMap,
            pOpenAcc->lineNo,
            pOpenAcc->endLineNo,
            pOpenAcc->funcLineNo,
            pOpenAcc->funcEndLineNo,
            pOpenAcc->cuDeviceId,
            pOpenAcc->cuContextId,
            pOpenAcc->cuStreamId,
            pOpenAcc->cuProcessId,
            pOpenAcc->cuThreadId,
            (unsigned long long)pOpenAcc->externalId);

    fprintf(pFileHandle, ", srcFile %s", pOpenAcc->srcFile ? pOpenAcc->srcFile : "?");
    fprintf(pFileHandle, ", funcName %s", pOpenAcc->funcName ? pOpenAcc->funcName : "?");

}

static void
PrintActivity(
    CUpti_Activity *pRecord,
    FILE *pFileHandle)
{
  CUpti_ActivityKind activityKind = pRecord->kind;

    switch (activityKind)
    {
        case CUPTI_ACTIVITY_KIND_MEMCPY:
        {
            CUpti_ActivityMemcpy6 *pMemcpyRecord = (CUpti_ActivityMemcpy6 *)pRecord;

            fprintf(pFileHandle, "%s \"%s\" [ %llu, %llu ] duration %llu, size %llu, copyCount %llu, srcKind %s, dstKind %s, correlationId %u\n"
                    "\tdeviceId %u, contextId %u, streamId %u, graphId %u, graphNodeId %llu, channelId %u, channelType %s\n",
                    GetActivityKindString(pMemcpyRecord->kind),
                    GetMemcpyKindString((CUpti_ActivityMemcpyKind)pMemcpyRecord->copyKind),
                    (unsigned long long)pMemcpyRecord->start,
                    (unsigned long long)pMemcpyRecord->end,
                    (unsigned long long)(pMemcpyRecord->end - pMemcpyRecord->start),
                    (unsigned long long)pMemcpyRecord->bytes,
                    (unsigned long long)pMemcpyRecord->copyCount,
                    GetMemoryKindString((CUpti_ActivityMemoryKind)pMemcpyRecord->srcKind),
                    GetMemoryKindString((CUpti_ActivityMemoryKind)pMemcpyRecord->dstKind),
                    pMemcpyRecord->correlationId,
                    pMemcpyRecord->deviceId,
                    pMemcpyRecord->contextId,
                    pMemcpyRecord->streamId,
                    pMemcpyRecord->graphId,
                    (unsigned long long)pMemcpyRecord->graphNodeId,
                    pMemcpyRecord->channelID,
                    GetChannelType(pMemcpyRecord->channelType));

            break;
        }
        case CUPTI_ACTIVITY_KIND_MEMSET:
        {
            CUpti_ActivityMemset4 *pMemsetRecord = (CUpti_ActivityMemset4 *)pRecord;

            fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, value %u, size %llu, correlationId %u\n"
                    "\tdeviceId %u, contextId %u, streamId %u, graphId %u, graphNodeId %llu, channelId %u, channelType %s\n",
                    GetActivityKindString(pMemsetRecord->kind),
                    (unsigned long long)pMemsetRecord->start,
                    (unsigned long long)pMemsetRecord->end,
                    (unsigned long long)(pMemsetRecord->end - pMemsetRecord->start),
                    pMemsetRecord->value,
                    (unsigned long long)pMemsetRecord->bytes,
                    pMemsetRecord->correlationId,
                    pMemsetRecord->deviceId,
                    pMemsetRecord->contextId,
                    pMemsetRecord->streamId,
                    pMemsetRecord->graphId,
                    (unsigned long long)pMemsetRecord->graphNodeId,
                    pMemsetRecord->channelID,
                    GetChannelType(pMemsetRecord->channelType));

            break;
        }
        case CUPTI_ACTIVITY_KIND_KERNEL:
        case CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL:
        {
            CUpti_ActivityKernel9 *pKernelRecord = (CUpti_ActivityKernel9 *)pRecord;

            fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, \"%s\", correlationId %u, cacheConfigRequested %d, cacheConfigExecuted %d\n"
                    "\tgrid [ %u, %u, %u ], block [ %u, %u, %u ], cluster [ %u, %u, %u ], sharedMemory (static %u, dynamic %u)\n"
                    "\tdeviceId %u, contextId %u, streamId %u, graphId %u, graphNodeId %llu, channelId %u, channelType %s\n",
                    GetActivityKindString(pKernelRecord->kind),
                    (unsigned long long)pKernelRecord->start,
                    (unsigned long long)pKernelRecord->end,
                    (unsigned long long)(pKernelRecord->end - pKernelRecord->start),
                    GetName(pKernelRecord->name),
                    pKernelRecord->correlationId,
                    pKernelRecord->cacheConfig.config.requested,
                    pKernelRecord->cacheConfig.config.executed,
                    pKernelRecord->gridX,
                    pKernelRecord->gridY,
                    pKernelRecord->gridZ,
                    pKernelRecord->blockX,
                    pKernelRecord->blockY,
                    pKernelRecord->blockZ,
                    pKernelRecord->clusterX,
                    pKernelRecord->clusterY,
                    pKernelRecord->clusterZ,
                    pKernelRecord->staticSharedMemory,
                    pKernelRecord->dynamicSharedMemory,
                    pKernelRecord->deviceId,
                    pKernelRecord->contextId,
                    pKernelRecord->streamId,
                    pKernelRecord->graphId,
                    (unsigned long long)pKernelRecord->graphNodeId,
                    pKernelRecord->channelID,
                    GetChannelType(pKernelRecord->channelType));

            break;
        }
        case CUPTI_ACTIVITY_KIND_DRIVER:
        case CUPTI_ACTIVITY_KIND_RUNTIME:
        case CUPTI_ACTIVITY_KIND_INTERNAL_LAUNCH_API:
        {
            CUpti_ActivityAPI *pApiRecord = (CUpti_ActivityAPI *)pRecord;
            const char* pName = NULL;

            if (pApiRecord->kind == CUPTI_ACTIVITY_KIND_DRIVER)
            {
                cuptiGetCallbackName(CUPTI_CB_DOMAIN_DRIVER_API, pApiRecord->cbid, &pName);
            }
            else if (pApiRecord->kind == CUPTI_ACTIVITY_KIND_RUNTIME)
            {
                cuptiGetCallbackName(CUPTI_CB_DOMAIN_RUNTIME_API, pApiRecord->cbid, &pName);
            }

            fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, \"%s\", cbid %u, processId %u, threadId %u, correlationId %u\n",
                    GetActivityKindString(pApiRecord->kind),
                    (unsigned long long)pApiRecord->start,
                    (unsigned long long)pApiRecord->end,
                    (unsigned long long)(pApiRecord->end - pApiRecord->start),
                    GetName(pName),
                    pApiRecord->cbid,
                    pApiRecord->processId,
                    pApiRecord->threadId,
                    pApiRecord->correlationId);

            break;
        }
        case CUPTI_ACTIVITY_KIND_DEVICE:
        {
            CUpti_ActivityDevice5 *pDeviceRecord = (CUpti_ActivityDevice5 *)pRecord;

            fprintf(pFileHandle, "%s %s [ %u ]\n",
                    GetActivityKindString(pDeviceRecord->kind),
                    GetName(pDeviceRecord->name),
                    pDeviceRecord->id);

            break;
        }
        case CUPTI_ACTIVITY_KIND_CONTEXT:
        {
            CUpti_ActivityContext3 *pContextRecord = (CUpti_ActivityContext3 *)pRecord;

            fprintf(pFileHandle, "%s computeApiKind %s, contextId %u, deviceId %u, nullStreamId %d, CIG mode %d\n",
                    GetActivityKindString(pContextRecord->kind),
                    GetComputeApiKindString((CUpti_ActivityComputeApiKind) pContextRecord->computeApiKind),
                    pContextRecord->contextId,
                    pContextRecord->deviceId,
                    (int)pContextRecord->nullStreamId,
                    pContextRecord->cigMode);

            break;
        }
        case CUPTI_ACTIVITY_KIND_NAME:
        {
            CUpti_ActivityName *pNameRecord = (CUpti_ActivityName *)pRecord;

            switch(pNameRecord->objectKind)
            {
                case CUPTI_ACTIVITY_OBJECT_CONTEXT:
                {
                    fprintf(pFileHandle, "%s %s %u %s id %u, name %s\n",
                            GetActivityKindString(pNameRecord->kind),
                            GetActivityObjectKindString(pNameRecord->objectKind),
                            GetActivityObjectKindId(pNameRecord->objectKind, &pNameRecord->objectId),
                            GetActivityObjectKindString(CUPTI_ACTIVITY_OBJECT_DEVICE),
                            GetActivityObjectKindId(CUPTI_ACTIVITY_OBJECT_DEVICE, &pNameRecord->objectId),
                            GetName(pNameRecord->name));

                    break;
                }
                case CUPTI_ACTIVITY_OBJECT_STREAM:
                {
                    fprintf(pFileHandle, "%s %s %u %s %u %s id %u, name %s\n",
                            GetActivityKindString(pNameRecord->kind),
                            GetActivityObjectKindString(pNameRecord->objectKind),
                            GetActivityObjectKindId(pNameRecord->objectKind, &pNameRecord->objectId),
                            GetActivityObjectKindString(CUPTI_ACTIVITY_OBJECT_CONTEXT),
                            GetActivityObjectKindId(CUPTI_ACTIVITY_OBJECT_CONTEXT, &pNameRecord->objectId),
                            GetActivityObjectKindString(CUPTI_ACTIVITY_OBJECT_DEVICE),
                            GetActivityObjectKindId(CUPTI_ACTIVITY_OBJECT_DEVICE, &pNameRecord->objectId),
                            GetName(pNameRecord->name));

                    break;
                }
                default:
                {
                    fprintf(pFileHandle, "%s %s id %u, name %s\n",
                            GetActivityKindString(pNameRecord->kind),
                            GetActivityObjectKindString(pNameRecord->objectKind),
                            GetActivityObjectKindId(pNameRecord->objectKind, &pNameRecord->objectId),
                            GetName(pNameRecord->name));
                    break;
                }
            }

            break;
        }
        case CUPTI_ACTIVITY_KIND_MARKER:
        {
            CUpti_ActivityMarker2 *pMarkerRecord = (CUpti_ActivityMarker2 *)pRecord;

            fprintf(pFileHandle, "%s [ %llu ] id %u, domain %s, name %s\n",
                    GetActivityKindString(pMarkerRecord->kind),
                    (unsigned long long)pMarkerRecord->timestamp,
                    pMarkerRecord->id,
                    GetDomainName(pMarkerRecord->domain),
                    GetName(pMarkerRecord->name));

            break;
        }
        case CUPTI_ACTIVITY_KIND_MARKER_DATA:
        {
            CUpti_ActivityMarkerData *pMarkerDataRecord = (CUpti_ActivityMarkerData *)pRecord;

            fprintf(pFileHandle, "%s id %u, color 0x%x, category %u, payload %llu/%f\n",
                    GetActivityKindString(pMarkerDataRecord->kind),
                    pMarkerDataRecord->id,
                    pMarkerDataRecord->color,
                    pMarkerDataRecord->category,
                    (unsigned long long)pMarkerDataRecord->payload.metricValueUint64,
                    pMarkerDataRecord->payload.metricValueDouble);

            break;
        }
        case CUPTI_ACTIVITY_KIND_SOURCE_LOCATOR:
        {
            CUpti_ActivitySourceLocator *pSourceLocatorRecord = (CUpti_ActivitySourceLocator *)pRecord;

            char line[LINE_SIZE];
            FILE *pLocalFileHandle = NULL;

            if ((pLocalFileHandle = fopen(pSourceLocatorRecord->fileName, "rt")) == NULL)
            {
                fprintf(pFileHandle, "Failed to open source file: %s\n", pSourceLocatorRecord->fileName);
            }
            else
            {
                uint32_t temp = 0;

                while (pSourceLocatorRecord->lineNumber > temp)
                {
                    if (fgets(line, LINE_SIZE, pLocalFileHandle) == NULL)
                    {
                        fprintf(pFileHandle, "Line %d could not be found in file %s.\n",
                                pSourceLocatorRecord->lineNumber, pSourceLocatorRecord->fileName);
                        break;
                    }

                    temp++;
                }
                fprintf(pFileHandle, "%d, %s", pSourceLocatorRecord-> id, line);
                fclose(pLocalFileHandle);
            }

            break;
        }
        case CUPTI_ACTIVITY_KIND_GLOBAL_ACCESS:
        {
            CUpti_ActivityGlobalAccess3 *pGlobalAccessRecord = (CUpti_ActivityGlobalAccess3 *)pRecord;

            fprintf(pFileHandle, "%s sourceLocatorId %u, functionId %u, pcOffset 0x%llx, correlationId %u, operation %s, isCached %s, size %u,\n"
                    "  executed %u, threadsExecuted %llu, transactions %llu, optimizedTransactions %llu\n",
                    GetActivityKindString(pGlobalAccessRecord->kind),
                    pGlobalAccessRecord->sourceLocatorId,
                    pGlobalAccessRecord->functionId,
                    (unsigned long long)pGlobalAccessRecord->pcOffset,
                    pGlobalAccessRecord->correlationId,
                    ((pGlobalAccessRecord->flags & CUPTI_ACTIVITY_FLAG_GLOBAL_ACCESS_KIND_LOAD) ? "Load" : "Store"),
                    ((pGlobalAccessRecord->flags & CUPTI_ACTIVITY_FLAG_GLOBAL_ACCESS_KIND_CACHED) ? "Yes" : "No"),
                    (uint32_t)(pGlobalAccessRecord->flags & CUPTI_ACTIVITY_FLAG_GLOBAL_ACCESS_KIND_SIZE_MASK),
                    pGlobalAccessRecord->executed,
                    (unsigned long long)pGlobalAccessRecord->threadsExecuted,
                    (unsigned long long)pGlobalAccessRecord->l2_transactions,
                    (unsigned long long)pGlobalAccessRecord->theoreticalL2Transactions);

            break;
        }
        case CUPTI_ACTIVITY_KIND_BRANCH:
        {
            CUpti_ActivityBranch2 *pBranchRecord = (CUpti_ActivityBranch2 *)pRecord;

            fprintf(pFileHandle, "%s sourceLocatorId %u, functionId %u, pcOffset 0x%x, correlationId %u,\n"
                    "  executed %u, threadsExecuted %llu, diverged %u\n",
                    GetActivityKindString(pBranchRecord->kind),
                    pBranchRecord->sourceLocatorId,
                    pBranchRecord->functionId,
                    pBranchRecord->pcOffset,
                    pBranchRecord->correlationId,
                    pBranchRecord->executed,
                    (unsigned long long)pBranchRecord->threadsExecuted,
                    pBranchRecord->diverged);

            break;
        }
        case CUPTI_ACTIVITY_KIND_OVERHEAD:
        {
            CUpti_ActivityOverhead3 *pOverheadRecord = (CUpti_ActivityOverhead3 *)pRecord;

            fprintf(pFileHandle, "%s %s [ %llu, %llu ] duration %llu, %s, id %u, correlation id %lu\n",
                    GetActivityKindString(pOverheadRecord->kind),
                    GetActivityOverheadKindString(pOverheadRecord->overheadKind),
                    (unsigned long long)pOverheadRecord->start,
                    (unsigned long long)pOverheadRecord->end,
                    (unsigned long long)(pOverheadRecord->end - pOverheadRecord->start),
                    GetActivityObjectKindString(pOverheadRecord->objectKind),
                    GetActivityObjectKindId(pOverheadRecord->objectKind, &pOverheadRecord->objectId),
                    (unsigned long)pOverheadRecord->correlationId);
            if (pOverheadRecord->overheadData)
            {
                switch (pOverheadRecord->overheadKind)
                {
                    case CUPTI_ACTIVITY_OVERHEAD_COMMAND_BUFFER_FULL:
                    {
                        CUpti_ActivityOverheadCommandBufferFullData* pCommandBufferData = (CUpti_ActivityOverheadCommandBufferFullData*)pOverheadRecord->overheadData;
                        fprintf(pFileHandle, "CUpti_ActivityOverheadCommandBufferFullData : commandBufferLength %d channelID %d channelType %d\n",
                        pCommandBufferData->commandBufferLength,
                        pCommandBufferData->channelID,
                        pCommandBufferData->channelType);
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }

            }

            break;
        }
        case CUPTI_ACTIVITY_KIND_CDP_KERNEL:
        {
            CUpti_ActivityCdpKernel *pCdpKernelRecord = (CUpti_ActivityCdpKernel *)pRecord;

            fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, \"%s\", deviceId %u, contextId %u, streamId %u, gridId %lld, correlationId %u,\n"
                    "\tgrid [ %u, %u, %u ], block [ %u, %u, %u ], registersPerThread %u, sharedMemory (static %u, dynamic %u), parentGridId %lld, parentBlockId [ %u, %u, %u ]\n",
                    GetActivityKindString(pCdpKernelRecord->kind),
                    (unsigned long long)pCdpKernelRecord->start,
                    (unsigned long long)pCdpKernelRecord->end,
                    (unsigned long long)(pCdpKernelRecord->end - pCdpKernelRecord->start),
                    GetName(pCdpKernelRecord->name),
                    pCdpKernelRecord->deviceId,
                    pCdpKernelRecord->contextId,
                    pCdpKernelRecord->streamId,
                    (long long)pCdpKernelRecord->gridId,
                    pCdpKernelRecord->correlationId,
                    pCdpKernelRecord->gridX,
                    pCdpKernelRecord->gridY,
                    pCdpKernelRecord->gridZ,
                    pCdpKernelRecord->blockX,
                    pCdpKernelRecord->blockY,
                    pCdpKernelRecord->blockZ,
                    pCdpKernelRecord->registersPerThread,
                    pCdpKernelRecord->staticSharedMemory,
                    pCdpKernelRecord->dynamicSharedMemory,
                    (long long)pCdpKernelRecord->parentGridId,
                    pCdpKernelRecord->parentBlockX,
                    pCdpKernelRecord->parentBlockY,
                    pCdpKernelRecord->parentBlockZ);

            break;
        }
        case CUPTI_ACTIVITY_KIND_PREEMPTION:
        {
            CUpti_ActivityPreemption *pPreemptionRecord = (CUpti_ActivityPreemption *)pRecord;

            fprintf(pFileHandle, "%s preemptionKind %s [ %llu ] gridId %lld, block [ %u, %u, %u ]\n",
                    GetActivityKindString(pPreemptionRecord->kind),
                    GetPreemptionKindString(pPreemptionRecord->preemptionKind),
                    (unsigned long long)pPreemptionRecord->timestamp,
                    (long long)pPreemptionRecord->gridId,
                    pPreemptionRecord->blockX,
                    pPreemptionRecord->blockY,
                    pPreemptionRecord->blockZ);

            break;
        }
        case CUPTI_ACTIVITY_KIND_ENVIRONMENT:
        {
            CUpti_ActivityEnvironment *pEnvironmentRecord = (CUpti_ActivityEnvironment *)pRecord;

            switch (pEnvironmentRecord->environmentKind)
            {
                case CUPTI_ACTIVITY_ENVIRONMENT_SPEED:
                {
                    fprintf(pFileHandle, "%s: kind=SPEED, deviceId %u, timestamp %llu, memoryClock %u, smClock %u, pcieLinkGen %u, pcieLinkWidth %u, clocksThrottleReasons %u\n",
                            GetActivityKindString(pEnvironmentRecord->kind),
                            pEnvironmentRecord->deviceId,
                            (unsigned long long)pEnvironmentRecord->timestamp,
                            pEnvironmentRecord->data.speed.memoryClock,
                            pEnvironmentRecord->data.speed.smClock,
                            pEnvironmentRecord->data.speed.pcieLinkGen,
                            pEnvironmentRecord->data.speed.pcieLinkWidth,
                            pEnvironmentRecord->data.speed.clocksThrottleReasons);

                    break;
                }
                case CUPTI_ACTIVITY_ENVIRONMENT_TEMPERATURE:
                {
                    fprintf(pFileHandle, "%s: kind=TEMPERATURE, deviceId %u, timestamp %llu, gpuTemperature %u\n",
                            GetActivityKindString(pEnvironmentRecord->kind),
                            pEnvironmentRecord->deviceId,
                            (unsigned long long)pEnvironmentRecord->timestamp,
                            pEnvironmentRecord->data.temperature.gpuTemperature);

                    break;
                }
                case CUPTI_ACTIVITY_ENVIRONMENT_POWER:
                {
                    fprintf(pFileHandle, "%s: kind=POWER, deviceId %u, timestamp %llu, power %u, powerLimit %u\n",
                            GetActivityKindString(pEnvironmentRecord->kind),
                            pEnvironmentRecord->deviceId,
                            (unsigned long long)pEnvironmentRecord->timestamp,
                            pEnvironmentRecord->data.power.power,
                            pEnvironmentRecord->data.power.powerLimit);

                    break;
                }
                case CUPTI_ACTIVITY_ENVIRONMENT_COOLING:
                {
                    fprintf(pFileHandle, "%s: kind=COOLING, deviceId %u, timestamp %llu, fanSpeed %u\n",
                            GetActivityKindString(pEnvironmentRecord->kind),
                            pEnvironmentRecord->deviceId,
                            (unsigned long long)pEnvironmentRecord->timestamp,
                            pEnvironmentRecord->data.cooling.fanSpeed);

                    break;
                }
                default:
                    break;
            }

            break;
        }
        case CUPTI_ACTIVITY_KIND_MEMCPY2:
        {
            CUpti_ActivityMemcpyPtoP4 *pMemcpyPtoPRecord = (CUpti_ActivityMemcpyPtoP4 *)pRecord;

            fprintf(pFileHandle, "%s \"%s\" [ %llu, %llu ] duration %llu, size %llu, srcKind %s, dstKind %s, correlationId %u,\n"
                    "\tdeviceId %u, contextId %u, streamId %u, graphId %u, graphNodeId %llu, channelId %u, channelType %s\n"
                    "\tsrcDeviceId %u, srcContextId %u, dstDeviceId %u, dstContextId %u\n",
                    GetActivityKindString(pMemcpyPtoPRecord->kind),
                    GetMemcpyKindString((CUpti_ActivityMemcpyKind)pMemcpyPtoPRecord->copyKind),
                    (unsigned long long)pMemcpyPtoPRecord->start,
                    (unsigned long long)pMemcpyPtoPRecord->end,
                    (unsigned long long)(pMemcpyPtoPRecord->end - pMemcpyPtoPRecord->start),
                    (unsigned long long)pMemcpyPtoPRecord->bytes,
                    GetMemoryKindString((CUpti_ActivityMemoryKind)pMemcpyPtoPRecord->srcKind),
                    GetMemoryKindString((CUpti_ActivityMemoryKind)pMemcpyPtoPRecord->dstKind),
                    pMemcpyPtoPRecord->correlationId,
                    pMemcpyPtoPRecord->deviceId,
                    pMemcpyPtoPRecord->contextId,
                    pMemcpyPtoPRecord->streamId,
                    pMemcpyPtoPRecord->graphId,
                    (unsigned long long)pMemcpyPtoPRecord->graphNodeId,
                    pMemcpyPtoPRecord->channelID,
                    GetChannelType(pMemcpyPtoPRecord->channelType),
                    pMemcpyPtoPRecord->srcDeviceId,
                    pMemcpyPtoPRecord->srcContextId,
                    pMemcpyPtoPRecord->dstDeviceId,
                    pMemcpyPtoPRecord->dstContextId);

            break;
        }
        case CUPTI_ACTIVITY_KIND_INSTRUCTION_EXECUTION:
        {
            CUpti_ActivityInstructionExecution *pInstructionExecutionRecord = (CUpti_ActivityInstructionExecution *)pRecord;

            fprintf(pFileHandle, "%s sourceLocatorId %u, functionId %u, pcOffset 0x%x, correlationId %u,\n"
                    "  valid %s, executed %u, threadsExecuted %llu, notPredOffThreadsExecuted %llu\n",
                    GetActivityKindString(pInstructionExecutionRecord->kind),
                    pInstructionExecutionRecord->sourceLocatorId,
                    pInstructionExecutionRecord->functionId,
                    pInstructionExecutionRecord->pcOffset,
                    pInstructionExecutionRecord->correlationId,
                    ((pInstructionExecutionRecord->flags & CUPTI_ACTIVITY_FLAG_INSTRUCTION_VALUE_INVALID) ? "no" : "yes"),
                    pInstructionExecutionRecord->executed,
                    (unsigned long long)pInstructionExecutionRecord->threadsExecuted,
                    (unsigned long long)pInstructionExecutionRecord->notPredOffThreadsExecuted);

            break;
        }
        case CUPTI_ACTIVITY_KIND_UNIFIED_MEMORY_COUNTER:
        {
            CUpti_ActivityUnifiedMemoryCounter2 *pUnifiedMemoryCounterRecord = (CUpti_ActivityUnifiedMemoryCounter2 *)pRecord;

            fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, counterKind %s, value %llu, address %llx, srcId %u, dstId %u, processId %u\n",
                    GetActivityKindString(pUnifiedMemoryCounterRecord->kind),
                    (unsigned long long)pUnifiedMemoryCounterRecord->start,
                    (unsigned long long)pUnifiedMemoryCounterRecord->end,
                    (unsigned long long)(pUnifiedMemoryCounterRecord->end - pUnifiedMemoryCounterRecord->start),
                    GetUvmCounterKindString(pUnifiedMemoryCounterRecord->counterKind),
                    (unsigned long long)pUnifiedMemoryCounterRecord->value,
                    (unsigned long long)pUnifiedMemoryCounterRecord->address,
                    pUnifiedMemoryCounterRecord->srcId,
                    pUnifiedMemoryCounterRecord->dstId,
                    pUnifiedMemoryCounterRecord->processId);

            break;
        }
        case CUPTI_ACTIVITY_KIND_FUNCTION:
        {
            CUpti_ActivityFunction *pFunctionRecord = (CUpti_ActivityFunction *)pRecord;

            fprintf(pFileHandle, "%s id %u, contextId %u, moduleId %u, functionIndex %u, name %s\n",
                    GetActivityKindString(pFunctionRecord->kind),
                    pFunctionRecord->id,
                    pFunctionRecord->contextId,
                    pFunctionRecord->moduleId,
                    pFunctionRecord->functionIndex,
                    GetName(pFunctionRecord->name));

            break;
        }
        case CUPTI_ACTIVITY_KIND_MODULE:
        {
            CUpti_ActivityModule *pModuleRecord = (CUpti_ActivityModule *)pRecord;

            fprintf(pFileHandle, "%s contextId %u, id %d, cubinSize %d\n",
                    GetActivityKindString(pModuleRecord->kind),
                    pModuleRecord->contextId,
                    pModuleRecord->id,
                    pModuleRecord->cubinSize);

            break;
        }
        case CUPTI_ACTIVITY_KIND_DEVICE_ATTRIBUTE:
        {
            CUpti_ActivityDeviceAttribute *pDeviceAttributeRecord = (CUpti_ActivityDeviceAttribute *)pRecord;

            fprintf(pFileHandle, "%s %u, deviceId %u, value 0x%llx\n",
                    GetActivityKindString(pDeviceAttributeRecord->kind),
                    pDeviceAttributeRecord->attribute.cupti,
                    pDeviceAttributeRecord->deviceId,
                    (unsigned long long)pDeviceAttributeRecord->value.vUint64);

            break;
        }
        case CUPTI_ACTIVITY_KIND_SHARED_ACCESS:
        {
            CUpti_ActivitySharedAccess *pSharedAccessRecord = (CUpti_ActivitySharedAccess *)pRecord;

            fprintf(pFileHandle, "%s sourceLocatorId %u, functionId %u, pcOffset 0x%x, correlationId %u,\n"
                    "  op %s, size %u, executed %u, threadsExecuted %llu, sharedTransactions %llu, optimizedTransactions %llu\n",
                    GetActivityKindString(pSharedAccessRecord->kind),
                    pSharedAccessRecord->sourceLocatorId,
                    pSharedAccessRecord->functionId,
                    pSharedAccessRecord->pcOffset,
                    pSharedAccessRecord->correlationId,
                    ((pSharedAccessRecord->flags & CUPTI_ACTIVITY_FLAG_SHARED_ACCESS_KIND_LOAD) ? "Load" : "Store"),
                    (uint32_t)(pSharedAccessRecord->flags & CUPTI_ACTIVITY_FLAG_SHARED_ACCESS_KIND_SIZE_MASK),
                    pSharedAccessRecord->executed,
                    (unsigned long long)pSharedAccessRecord->threadsExecuted,
                    (unsigned long long)pSharedAccessRecord->sharedTransactions,
                    (unsigned long long)pSharedAccessRecord->theoreticalSharedTransactions);

            break;
        }
        case CUPTI_ACTIVITY_KIND_PC_SAMPLING:
        {
            CUpti_ActivityPCSampling3 *pPcSamplingRecord = (CUpti_ActivityPCSampling3 *)pRecord;

            fprintf(pFileHandle, "%s sourceLocatorId %u, functionId %u, pcOffset 0x%llx, correlationId %u, samples %u, latencySamples %u, stallReason %s\n",
                    GetActivityKindString(pPcSamplingRecord->kind),
                    pPcSamplingRecord->sourceLocatorId,
                    pPcSamplingRecord->functionId,
                    (unsigned long long)pPcSamplingRecord->pcOffset,
                    pPcSamplingRecord->correlationId,
                    pPcSamplingRecord->samples,
                    pPcSamplingRecord->latencySamples,
                    GetStallReasonString(pPcSamplingRecord->stallReason));

            break;
        }
        case CUPTI_ACTIVITY_KIND_PC_SAMPLING_RECORD_INFO:
        {
            CUpti_ActivityPCSamplingRecordInfo *pPcSamplingRecordInfo = (CUpti_ActivityPCSamplingRecordInfo *)pRecord;

            fprintf(pFileHandle, "%s correlationId %u, totalSamples %llu, droppedSamples %llu, samplingPeriodInCycles %llu\n",
                    GetActivityKindString(pPcSamplingRecordInfo->kind),
                    pPcSamplingRecordInfo->correlationId,
                    (unsigned long long)pPcSamplingRecordInfo->totalSamples,
                    (unsigned long long)pPcSamplingRecordInfo->droppedSamples,
                    (unsigned long long)pPcSamplingRecordInfo->samplingPeriodInCycles);

            break;
        }
        case CUPTI_ACTIVITY_KIND_INSTRUCTION_CORRELATION:
        {
            CUpti_ActivityInstructionCorrelation *pInstructionCorrelationRecord = (CUpti_ActivityInstructionCorrelation *)pRecord;

            fprintf(pFileHandle, "%s sourceLocatorId %u, functionId %u, pcOffset 0x%x\n",
                    GetActivityKindString(pInstructionCorrelationRecord->kind),
                    pInstructionCorrelationRecord->sourceLocatorId,
                    pInstructionCorrelationRecord->functionId,
                    pInstructionCorrelationRecord->pcOffset);

            break;
        }
        case CUPTI_ACTIVITY_KIND_OPENACC_DATA:
        {
            CUpti_ActivityOpenAccData *pOpenaccDataRecord = (CUpti_ActivityOpenAccData *)pRecord;

            PrintOpenaccCommon(pFileHandle, (CUpti_ActivityOpenAcc*)pOpenaccDataRecord);

            fprintf(pFileHandle, ", bytes %llu, varName %s\n",
                    (long long unsigned)pOpenaccDataRecord->bytes,
                    pOpenaccDataRecord->varName ? pOpenaccDataRecord->varName : "?");

            break;
        }
        case CUPTI_ACTIVITY_KIND_OPENACC_LAUNCH:
        {
            CUpti_ActivityOpenAccLaunch *pOpenaccLaunchRecord = (CUpti_ActivityOpenAccLaunch *)pRecord;

            PrintOpenaccCommon(pFileHandle, (CUpti_ActivityOpenAcc*)pOpenaccLaunchRecord);

            fprintf(pFileHandle, ", numGangs %llu, numWorkers %llu, vectorLength %llu, kernelName %s\n",
                    (long long unsigned)pOpenaccLaunchRecord->numGangs,
                    (long long unsigned)pOpenaccLaunchRecord->numWorkers,
                    (long long unsigned)pOpenaccLaunchRecord->vectorLength,
                    pOpenaccLaunchRecord->kernelName ? pOpenaccLaunchRecord->kernelName : "?");

            break;
        }
        case CUPTI_ACTIVITY_KIND_OPENACC_OTHER:
        {
            CUpti_ActivityOpenAccOther *pOpenaccOtherRecord = (CUpti_ActivityOpenAccOther *)pRecord;

            PrintOpenaccCommon(pFileHandle, (CUpti_ActivityOpenAcc*)pOpenaccOtherRecord);
            printf("\n");

            break;
        }
        case CUPTI_ACTIVITY_KIND_CUDA_EVENT:
        {
            CUpti_ActivityCudaEvent2 *pCudaEventRecord = (CUpti_ActivityCudaEvent2 *)pRecord;

            fprintf(pFileHandle, "%s [ %llu ] contextId %u, streamId %u, correlationId %u, eventId %u, cudaEventSyncId %llu\n",
                    GetActivityKindString(pCudaEventRecord->kind),
                    (long long unsigned)pCudaEventRecord->deviceTimestamp,
                    pCudaEventRecord->contextId,
                    pCudaEventRecord->streamId,
                    pCudaEventRecord->correlationId,
                    pCudaEventRecord->eventId,
                    (long long unsigned)pCudaEventRecord->cudaEventSyncId);

            break;
        }
        case CUPTI_ACTIVITY_KIND_STREAM:
        {
            CUpti_ActivityStream *pStreamRecord = (CUpti_ActivityStream *)pRecord;

            fprintf(pFileHandle, "%s type %s, priority %u, contextId %u, streamId %u, correlationId %u\n",
                    GetActivityKindString(pStreamRecord->kind),
                    GetStreamType(pStreamRecord->flag),
                    pStreamRecord->priority,
                    pStreamRecord->contextId,
                    pStreamRecord->streamId,
                    pStreamRecord->correlationId);
            break;
        }
        case CUPTI_ACTIVITY_KIND_SYNCHRONIZATION:
        {
            CUpti_ActivitySynchronization2 *pSynchronizationRecord = (CUpti_ActivitySynchronization2 *)pRecord;

            fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, type %s, contextId %u, streamId %d, correlationId %u, eventId %d, cudaEventSyncId %llu\n",
                    GetActivityKindString(pSynchronizationRecord->kind),
                    (unsigned long long)pSynchronizationRecord->start,
                    (unsigned long long)pSynchronizationRecord->end,
                    (unsigned long long)(pSynchronizationRecord->end - pSynchronizationRecord->start),
                    GetSynchronizationType(pSynchronizationRecord->type),
                    pSynchronizationRecord->contextId,
                    (int32_t)pSynchronizationRecord->streamId,
                    pSynchronizationRecord->correlationId,
                    (int32_t)pSynchronizationRecord->cudaEventId,
                    (long long unsigned)pSynchronizationRecord->cudaEventSyncId);

            break;
        }
        case CUPTI_ACTIVITY_KIND_EXTERNAL_CORRELATION:
        {
            CUpti_ActivityExternalCorrelation *pExternalCorrelationRecord = (CUpti_ActivityExternalCorrelation *)pRecord;

            fprintf(pFileHandle, "%s externalKind %s, correlationId %llu, externalId %llu\n",
                    GetActivityKindString(pExternalCorrelationRecord->kind),
                    GetExternalCorrelationKindString(pExternalCorrelationRecord->externalKind),
                    (long long unsigned)pExternalCorrelationRecord->correlationId,
                    (long long unsigned)pExternalCorrelationRecord->externalId);

            break;
        }
        case CUPTI_ACTIVITY_KIND_NVLINK:
        {
            CUpti_ActivityNvLink4 *pNvLinkRecord = (CUpti_ActivityNvLink4 *)pRecord;
            unsigned int i = 0;

            fprintf(pFileHandle, "%s typeDev0 %s, typeDev1 %s, sysmem %d, peer %d, physicalNvLinkCount %d, ",
                    GetActivityKindString(pNvLinkRecord->kind),
                    GetDevTypeNvlink(pNvLinkRecord->typeDev0),
                    GetDevTypeNvlink(pNvLinkRecord->typeDev1),
                    ((pNvLinkRecord->flag & CUPTI_LINK_FLAG_SYSMEM_ACCESS) ? 1 : 0),
                    ((pNvLinkRecord->flag & CUPTI_LINK_FLAG_PEER_ACCESS) ? 1 : 0),
                    pNvLinkRecord->physicalNvLinkCount);

            fprintf(pFileHandle, "portDev0 ");
            for (i = 0 ; i < pNvLinkRecord->physicalNvLinkCount ; i++ )
            {
                fprintf(pFileHandle, "%d, ", pNvLinkRecord->portDev0[i]);
            }


            fprintf(pFileHandle, "portDev1 ");
            for (i = 0 ; i < pNvLinkRecord->physicalNvLinkCount ; i++ )
            {
                fprintf(pFileHandle, "%d, ", pNvLinkRecord->portDev1[i]);
            }

            fprintf(pFileHandle, "bandwidth %llu\n", (long long unsigned int)pNvLinkRecord->bandwidth);

            break;
        }
        case CUPTI_ACTIVITY_KIND_MEMORY:
        {
            CUpti_ActivityMemory *pMemoryRecord = (CUpti_ActivityMemory *)(void *)pRecord;

            fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, size %llu bytes, address %llu, memoryKind %s, deviceId %u, contextId %u, processId %u\n",
                    GetActivityKindString(pMemoryRecord->kind),
                    (unsigned long long)pMemoryRecord->start,
                    (unsigned long long)pMemoryRecord->end,
                    (unsigned long long)(pMemoryRecord->end - pMemoryRecord->start),
                    (unsigned long long)pMemoryRecord->bytes,
                    (unsigned long long)pMemoryRecord->address,
                    GetMemoryKindString(pMemoryRecord->memoryKind),
                    pMemoryRecord->deviceId,
                    pMemoryRecord->contextId,
                    pMemoryRecord->processId);

            break;
        }
        case CUPTI_ACTIVITY_KIND_PCIE:
        {
            CUpti_ActivityPcie *pPcieRecord = (CUpti_ActivityPcie *)pRecord;

            if (pPcieRecord->type == CUPTI_PCIE_DEVICE_TYPE_GPU)
            {
                fprintf(pFileHandle, "%s GPU %u, domain %u, upstreamBus %u, link rate %u GT/s, link width %u bits.\n",
                        GetActivityKindString(pPcieRecord->kind),
                        pPcieRecord->id.devId,
                        pPcieRecord->domain,
                        pPcieRecord->upstreamBus,
                        pPcieRecord->linkRate,
                        pPcieRecord->linkWidth);
            }
            else if (pPcieRecord->type == CUPTI_PCIE_DEVICE_TYPE_BRIDGE)
            {
                fprintf(pFileHandle, "%s bridgeId %u, domain %u, upstream Bus %u, downstream Bus %u, link rate %u GT/s, link width %u bits.\n",
                        GetActivityKindString(pPcieRecord->kind),
                        pPcieRecord->id.bridgeId,
                        pPcieRecord->domain,
                        pPcieRecord->upstreamBus,
                        pPcieRecord->attr.bridgeAttr.secondaryBus,
                        pPcieRecord->linkRate,
                        pPcieRecord->linkWidth);
            }

            break;
        }
        case CUPTI_ACTIVITY_KIND_OPENMP:
        {
            CUpti_ActivityOpenMp *pOpenMpRecord = (CUpti_ActivityOpenMp *)pRecord;

            fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, eventKind %u, cuProcessId %u, cuThreadId %u\n",
                    GetActivityKindString(pOpenMpRecord->kind),
                    (unsigned long long)pOpenMpRecord->start,
                    (unsigned long long)pOpenMpRecord->end,
                    (unsigned long long)(pOpenMpRecord->end - pOpenMpRecord->start),
                    pOpenMpRecord->eventKind,
                    pOpenMpRecord->cuProcessId,
                    pOpenMpRecord->cuThreadId);

            break;
        }
        case CUPTI_ACTIVITY_KIND_MEMORY2:
        {
            CUpti_ActivityMemory4 *pMemory2Record = (CUpti_ActivityMemory4 *)(void *)pRecord;

            fprintf(pFileHandle, "%s [ %llu ] memoryOperationType %s, memoryKind %s, size %llu, address %llu, pc %llu,\n"
                    "  deviceId %u, contextId %u, streamId %u, processId %u, correlationId %u, isAsync %u,\n"
                    "  memoryPool %s, memoryPoolAddress %llu,  memoryPoolThreshold %llu\n"
                    "  source %s\n"
                    ,
                    GetActivityKindString(pMemory2Record->kind),
                    (unsigned long long)pMemory2Record->timestamp,
                    GetMemoryOperationTypeString(pMemory2Record->memoryOperationType),
                    GetMemoryKindString(pMemory2Record->memoryKind),
                    (unsigned long long)pMemory2Record->bytes,
                    (unsigned long long)pMemory2Record->address,
                    (unsigned long long)pMemory2Record->PC,
                    pMemory2Record->deviceId,
                    pMemory2Record->contextId,
                    pMemory2Record->streamId,
                    pMemory2Record->processId,
                    pMemory2Record->correlationId,
                    pMemory2Record->isAsync,
                    GetMemoryPoolTypeString(pMemory2Record->memoryPoolConfig.memoryPoolType),
                    (unsigned long long)pMemory2Record->memoryPoolConfig.address,
                    (unsigned long long)pMemory2Record->memoryPoolConfig.releaseThreshold
                    ,pMemory2Record->source
                    );

            if (pMemory2Record->memoryPoolConfig.memoryPoolType == CUPTI_ACTIVITY_MEMORY_POOL_TYPE_LOCAL)
            {
                fprintf(pFileHandle, ", memoryPoolSize: %llu, memoryPoolUtilizedSize: %llu",
                        (unsigned long long)pMemory2Record->memoryPoolConfig.pool.size,
                        (unsigned long long)pMemory2Record->memoryPoolConfig.utilizedSize);
            }
            else if (pMemory2Record->memoryPoolConfig.memoryPoolType == CUPTI_ACTIVITY_MEMORY_POOL_TYPE_IMPORTED)
            {
                fprintf(pFileHandle, ", memoryPoolProcessId: %llu",
                        (unsigned long long)pMemory2Record->memoryPoolConfig.pool.processId);
            }

            fprintf(pFileHandle, "\n");

            break;
        }
        case CUPTI_ACTIVITY_KIND_MEMORY_POOL:
        {
            CUpti_ActivityMemoryPool2 *pMemoryPoolRecord = (CUpti_ActivityMemoryPool2 *)(void *)pRecord;

            fprintf(pFileHandle, "%s [ %llu ] memoryPoolOperation %s, memoryPool %s, address %llu, size %llu, utilizedSize %llu, releaseThreshold %llu,\n"
                    "  deviceId %u, processId %u, correlationId %u\n",
                    GetActivityKindString(pMemoryPoolRecord->kind),
                    (unsigned long long)pMemoryPoolRecord->timestamp,
                    GetMemoryPoolOperationTypeString(pMemoryPoolRecord->memoryPoolOperationType),
                    GetMemoryPoolTypeString(pMemoryPoolRecord->memoryPoolType),
                    (unsigned long long)pMemoryPoolRecord->address,
                    (unsigned long long)pMemoryPoolRecord->size,
                    (unsigned long long)pMemoryPoolRecord->utilizedSize,
                    (unsigned long long)pMemoryPoolRecord->releaseThreshold,
                    pMemoryPoolRecord->deviceId,
                    pMemoryPoolRecord->processId,
                    pMemoryPoolRecord->correlationId);

            break;
        }
        case CUPTI_ACTIVITY_KIND_GRAPH_TRACE:
        {
            CUpti_ActivityGraphTrace2 *pGraphTraceRecord = (CUpti_ActivityGraphTrace2 *)pRecord;

            fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, correlationId %u\n deviceId %u, contextId %u, streamId %u, graphId %u\n",
                    GetActivityKindString(pGraphTraceRecord->kind),
                    (unsigned long long)pGraphTraceRecord->start,
                    (unsigned long long)pGraphTraceRecord->end,
                    (unsigned long long)(pGraphTraceRecord->end - pGraphTraceRecord->start),
                    pGraphTraceRecord->correlationId,
                    pGraphTraceRecord->deviceId,
                    pGraphTraceRecord->contextId,
                    pGraphTraceRecord->streamId,
                    pGraphTraceRecord->graphId);

            break;
        }
        case CUPTI_ACTIVITY_KIND_JIT:
        {
            CUpti_ActivityJit2 *pJitRecord = (CUpti_ActivityJit2 *)pRecord;

            fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, deviceId %u, correlationId %u, processId %u, threadId %u\n"
                    "jitEntryType %s, jitOperationType %s, jitOperationCorrelationId %llu\n cacheSize %llu, cachePath %s\n",
                    GetActivityKindString(pJitRecord->kind),
                    (unsigned long long)pJitRecord->start,
                    (unsigned long long)pJitRecord->end,
                    (unsigned long long)(pJitRecord->end - pJitRecord->start),
                    pJitRecord->deviceId,
                    pJitRecord->correlationId,
                    pJitRecord->processId,
                    pJitRecord->threadId,
                    GetJitEntryType(pJitRecord->jitEntryType),
                    GetJitOperationType(pJitRecord->jitOperationType),
                    (unsigned long long)pJitRecord->jitOperationCorrelationId,
                    (unsigned long long)pJitRecord->cacheSize,
                    GetName(pJitRecord->cachePath));

            break;
        }
        case CUPTI_ACTIVITY_KIND_MEM_DECOMPRESS:
        {
            CUpti_ActivityMemDecompress *pMemDecompress = (CUpti_ActivityMemDecompress *)pRecord;

            fprintf(pFileHandle, "%s [ %llu, %llu ] duration %llu, deviceId %u, contextId %u, streamId %u, correlationId %u\n"
                    "channelId %u, channelType %s, numberOfOperations %u, sourceBytes %llu\n",
                    GetActivityKindString(pMemDecompress->kind),
                    (unsigned long long)pMemDecompress->start,
                    (unsigned long long)pMemDecompress->end,
                    (unsigned long long)(pMemDecompress->end - pMemDecompress->start),
                    pMemDecompress->deviceId,
                    pMemDecompress->contextId,
                    pMemDecompress->streamId,
                    pMemDecompress->correlationId,
                    pMemDecompress->channelID,
                    GetChannelType(pMemDecompress->channelType),
                    pMemDecompress->numberOfOperations,
                    (unsigned long long)pMemDecompress->sourceBytes);

            break;
        }
        default:
            fprintf(pFileHandle, "  <unknown>\n");
            break;
    }
}

static void
PrintActivityBuffer(
    uint8_t *pBuffer,
    size_t validBytes,
    FILE *pFileHandle,
    void *pUserData)
{
    CUpti_Activity *pRecord = NULL;
    CUptiResult status = CUPTI_SUCCESS;

    do
    {
        status = cuptiActivityGetNextRecord(pBuffer, validBytes, &pRecord);
        if (status == CUPTI_SUCCESS)
        {
            if (!pUserData ||
                (pUserData && ((UserData *)pUserData)->printActivityRecords))
            {
                PrintActivity(pRecord, pFileHandle);
            }

            if (pUserData &&
                ((UserData *)pUserData)->pPostProcessActivityRecords)
            {
                ((UserData *)pUserData)->pPostProcessActivityRecords(pRecord);
            }
        }
        else if (status == CUPTI_ERROR_MAX_LIMIT_REACHED)
        {
            break;
        }
        else if (status == CUPTI_ERROR_INVALID_KIND)
        {
            break;
        }
        else
        {
            CUPTI_API_CALL(status);
        }
    } while (1);
}

// Buffer Management Functions
static void CUPTIAPI
BufferRequested(
    uint8_t **ppBuffer,
    size_t *pSize,
    size_t *pMaxNumRecords)
{
    uint8_t *pBuffer = (uint8_t *) malloc(globals.activityBufferSize + ALIGN_SIZE);
    MEMORY_ALLOCATION_CALL(pBuffer);

    *pSize = globals.activityBufferSize;
    *ppBuffer = ALIGN_BUFFER(pBuffer, ALIGN_SIZE);
    *pMaxNumRecords = 0;

    globals.buffersRequested++;
}

static void CUPTIAPI
BufferCompleted(
    CUcontext context,
    uint32_t streamId,
    uint8_t *pBuffer,
    size_t size,
    size_t validSize)
{
    if (validSize > 0)
    {
        FILE *pOutputFile = globals.pOutputFile;
        if (!pOutputFile)
        {
            pOutputFile = stdout;
        }

        PrintActivityBuffer(pBuffer, validSize, pOutputFile, globals.pUserData);
    }

    globals.buffersCompleted++;
    free(pBuffer);
}

// CUPTI callback functions
static void
HandleSyncronizationCallbacks(
    CUpti_CallbackId callbackId,
    const CUpti_SynchronizeData *pSynchronizeData,
    void *pUserData)
{
    // Flush the CUPTI activity records buffer on context synchronization
    if (callbackId == CUPTI_CBID_SYNCHRONIZE_CONTEXT_SYNCHRONIZED &&
        ((UserData *)pUserData)->flushAtCtxSync)
    {
        CUPTI_API_CALL_VERBOSE(cuptiActivityFlushAll(0));
    }
    // Flush the CUPTI activity records buffer on stream synchronization
    else if (callbackId == CUPTI_CBID_SYNCHRONIZE_STREAM_SYNCHRONIZED &&
            ((UserData *)pUserData)->flushAtStreamSync)
    {
        uint32_t streamId = 0;
        CUPTI_API_CALL_VERBOSE(cuptiGetStreamId(pSynchronizeData->context, pSynchronizeData->stream, &streamId));
        CUPTI_API_CALL_VERBOSE(cuptiActivityFlushAll(0));
    }
}

static void
HandleDomainStateCallback(
    CUpti_CallbackId callbackId,
    const CUpti_StateData *pStateData)
{
    switch (callbackId)
    {
        case CUPTI_CBID_STATE_FATAL_ERROR:
        {
            const char *errorString = NULL;
            cuptiGetResultString(pStateData->notification.result, &errorString);

            fprintf(globals.pOutputFile, "\nCUPTI encountered fatal error: %s\n", errorString);
            fprintf(globals.pOutputFile, "Error message: %s\n", pStateData->notification.message);

            // Exiting the application if fatal error encountered in CUPTI
            // If there is a CUPTI fatal error, it means CUPTI has stopped profiling the application.
            exit(EXIT_FAILURE);
        }
        default:
            break;
    }
}

static void CUPTIAPI
CuptiCallbackHandler(
    void *pUserData,
    CUpti_CallbackDomain domain,
    CUpti_CallbackId callbackId,
    const void *pCallbackData)
{
    CUPTI_API_CALL(cuptiGetLastError());

    if (((UserData *)pUserData)->printCallbacks &&
        globals.pOutputFile != NULL)
    {
        fprintf(globals.pOutputFile, "CUPTI Callback: Domain %d CbId %d\n", domain, callbackId);
        fflush(globals.pOutputFile);
    }

    const CUpti_CallbackData *pCallabckInfo = (CUpti_CallbackData *)pCallbackData;

    switch (domain)
    {
        case CUPTI_CB_DOMAIN_STATE:
            HandleDomainStateCallback(callbackId, (CUpti_StateData *)pCallbackData);
            break;
        case CUPTI_CB_DOMAIN_RUNTIME_API:
            switch (callbackId)
            {
                case CUPTI_RUNTIME_TRACE_CBID_cudaDeviceReset_v3020:
                    if (pCallabckInfo->callbackSite == CUPTI_API_ENTER)
                    {
                        CUPTI_API_CALL_VERBOSE(cuptiActivityFlushAll(0));
                    }
                    break;
                default:
                    break;
            }
            break;
        case CUPTI_CB_DOMAIN_SYNCHRONIZE:
            HandleSyncronizationCallbacks(callbackId, (CUpti_SynchronizeData *)pCallbackData, pUserData);
            break;
        default:
            break;
    }
}

// CUPTI Trace Setup
static void
InitCuptiTrace(
    void *pUserData,
    void *pTraceCallback,
    FILE *pFileHandle)
{
    if (!pUserData)
    {
        std::cerr << "Invalid parameter pUserData.\n";
        exit(EXIT_FAILURE);
    }

    globals.pOutputFile  = pFileHandle;
    globals.pUserData    = pUserData;

    // Subscribe to CUPTI
    if (((UserData *)pUserData)->skipCuptiSubscription == 0)
    {
        // If the user provides function pointer, subscribe CUPTI to that function pointer (pTraceCallback).
        // Else subscribe CUPTI to the common CuptiCallbackHandler.
        if (pTraceCallback)
        {
            CUPTI_API_CALL_VERBOSE(cuptiSubscribe(&globals.subscriberHandle, (CUpti_CallbackFunc)pTraceCallback, pUserData));
        }
        else
        {
            CUPTI_API_CALL_VERBOSE(cuptiSubscribe(&globals.subscriberHandle, (CUpti_CallbackFunc)CuptiCallbackHandler, pUserData));
        }


        // Enable CUPTI callback on context syncronization
        if (((UserData *)pUserData)->flushAtCtxSync)
        {
            CUPTI_API_CALL_VERBOSE(cuptiEnableCallback(1, globals.subscriberHandle, CUPTI_CB_DOMAIN_SYNCHRONIZE, CUPTI_CBID_SYNCHRONIZE_CONTEXT_SYNCHRONIZED));
        }

        // Enable CUPTI callback on stream syncronization
        if (((UserData *)pUserData)->flushAtStreamSync)
        {
            CUPTI_API_CALL_VERBOSE(cuptiEnableCallback(1, globals.subscriberHandle, CUPTI_CB_DOMAIN_SYNCHRONIZE, CUPTI_CBID_SYNCHRONIZE_STREAM_SYNCHRONIZED));
        }

        // Enable CUPTI callback on CUDA device reset by default
        CUPTI_API_CALL_VERBOSE(cuptiEnableCallback(1, globals.subscriberHandle, CUPTI_CB_DOMAIN_RUNTIME_API, CUPTI_RUNTIME_TRACE_CBID_cudaDeviceReset_v3020));

        // Enable CUPTI callback on fatal errors by default
        CUPTI_API_CALL_VERBOSE(cuptiEnableCallback(1, globals.subscriberHandle, CUPTI_CB_DOMAIN_STATE, CUPTI_CBID_STATE_FATAL_ERROR));
    }

    // Register callbacks for buffer requests and for buffers completed by CUPTI.
    globals.buffersRequested = 0;
    globals.buffersCompleted = 0;
    CUPTI_API_CALL_VERBOSE(cuptiActivityRegisterCallbacks(BufferRequested, BufferCompleted));

    // Optionally get and set activity attributes.
    // Attributes can be set by the CUPTI client to change behavior of the activity API.
    // Some attributes require to be set before any CUDA context is created to be effective,
    // E.g. To be applied to all device buffer allocations (see documentation).
    if ((((UserData *)pUserData))->deviceBufferSize != 0)
    {
        size_t attrValue = (((UserData *)pUserData))->deviceBufferSize;
        size_t attrValueSize = sizeof(size_t);
        CUPTI_API_CALL_VERBOSE(cuptiActivitySetAttribute(CUPTI_ACTIVITY_ATTR_DEVICE_BUFFER_SIZE, &attrValueSize, &attrValue));
        std::cout << "CUPTI_ACTIVITY_ATTR_DEVICE_BUFFER_SIZE = " << attrValue << " bytes.\n";
    }

    if ((((UserData *)pUserData))->activityBufferSize != 0)
    {
        globals.activityBufferSize = (((UserData *)pUserData))->activityBufferSize;
    }
    else
    {
        globals.activityBufferSize = BUF_SIZE;
    }

    std::cout << "Activity buffer size = " << globals.activityBufferSize << " bytes.\n";
}

static void
DeInitCuptiTrace(void)
{
    CUPTI_API_CALL(cuptiGetLastError());

    if (globals.subscriberHandle)
    {
        CUPTI_API_CALL_VERBOSE(cuptiUnsubscribe(globals.subscriberHandle));
    }

    CUPTI_API_CALL_VERBOSE(cuptiActivityFlushAll(1));

    if (globals.pUserData != NULL)
    {
        free(globals.pUserData);
    }
}

#endif // HELPER_CUPTI_ACTIVITY_H_
