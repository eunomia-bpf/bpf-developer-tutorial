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

#ifndef HELPER_CUPTI_H_
#define HELPER_CUPTI_H_

#pragma once

#include <iostream>

#ifndef EXIT_WAIVED
#define EXIT_WAIVED 2
#endif

#if defined(WIN32) || defined(_WIN32)
#define stricmp _stricmp
#else
#define stricmp strcasecmp
#endif

#define CUDA_MAX_DEVICES    256     // consider theoretical max devices as 256
#define DEV_NAME_LEN 256

#ifndef DRIVER_API_CALL
#define DRIVER_API_CALL(apiFunctionCall)                                            \
do                                                                                  \
{                                                                                   \
    CUresult _status = apiFunctionCall;                                             \
    if (_status != CUDA_SUCCESS)                                                    \
    {                                                                               \
        const char *pErrorString;                                                   \
        cuGetErrorString(_status, &pErrorString);                                   \
                                                                                    \
        std::cerr << "\n\nError: " << __FILE__ << ":" << __LINE__ << ": Function "  \
        << #apiFunctionCall << " failed with error(" << _status << "): "            \
        << pErrorString << ".\n\n";                                                 \
                                                                                    \
        exit(EXIT_FAILURE);                                                         \
    }                                                                               \
} while (0)
#endif

#ifndef RUNTIME_API_CALL
#define RUNTIME_API_CALL(apiFunctionCall)                                           \
do                                                                                  \
{                                                                                   \
    cudaError_t _status = apiFunctionCall;                                          \
    if (_status != cudaSuccess)                                                     \
    {                                                                               \
        std::cerr << "\n\nError: " << __FILE__ << ":" << __LINE__ << ": Function "  \
        << #apiFunctionCall << " failed with error(" << _status << "): "            \
        << cudaGetErrorString(_status) << ".\n\n";                                  \
                                                                                    \
        exit(EXIT_FAILURE);                                                         \
    }                                                                               \
} while (0)
#endif

#ifndef CUPTI_API_CALL
#define CUPTI_API_CALL(apiFunctionCall)                                             \
do                                                                                  \
{                                                                                   \
    CUptiResult _status = apiFunctionCall;                                          \
    if (_status != CUPTI_SUCCESS)                                                   \
    {                                                                               \
        const char *pErrorString;                                                   \
        cuptiGetResultString(_status, &pErrorString);                               \
                                                                                    \
        std::cerr << "\n\nError: " << __FILE__ << ":" << __LINE__ << ": Function "  \
        << #apiFunctionCall << " failed with error(" << _status << "): "            \
        << pErrorString << ".\n\n";                                                 \
                                                                                    \
        exit(EXIT_FAILURE);                                                         \
    }                                                                               \
} while (0)
#endif

#ifndef CUPTI_API_CALL_VERBOSE
#define CUPTI_API_CALL_VERBOSE(apiFunctionCall)                                     \
do                                                                                  \
{                                                                                   \
    std::cout << "Calling CUPTI API: " << #apiFunctionCall << "\n";                 \
                                                                                    \
    CUptiResult _status = apiFunctionCall;                                          \
    if (_status != CUPTI_SUCCESS)                                                   \
    {                                                                               \
        const char *pErrorString;                                                   \
        cuptiGetResultString(_status, &pErrorString);                               \
                                                                                    \
        std::cerr << "\n\nError: " << __FILE__ << ":" << __LINE__ << ": Function "  \
        << #apiFunctionCall << " failed with error(" << _status << "): "            \
        << pErrorString << ".\n\n";                                                 \
                                                                                    \
        exit(EXIT_FAILURE);                                                         \
    }                                                                               \
} while (0)
#endif

#ifndef CUPTI_UTIL_CALL
#define CUPTI_UTIL_CALL(apiFunctionCall)                                            \
do                                                                                  \
{                                                                                   \
    CUptiUtilResult _status = apiFunctionCall;                                      \
    if (_status != CUPTI_UTIL_SUCCESS)                                              \
    {                                                                               \
        std::cerr << "\n\nError: " << __FILE__ << ":" << __LINE__ << ": Function "  \
        << #apiFunctionCall << " failed with error: " << _status << "\n\n";         \
                                                                                    \
        exit(EXIT_FAILURE);                                                         \
    }                                                                               \
} while (0)
#endif

#ifndef NVPW_API_CALL
#define NVPW_API_CALL(apiFunctionCall)                                              \
do                                                                                  \
{                                                                                   \
    NVPA_Status _status = apiFunctionCall;                                          \
    if (_status != NVPA_STATUS_SUCCESS)                                             \
    {                                                                               \
        std::cerr << "\n\nError: " << __FILE__ << ":" << __LINE__ << ": Function "  \
        << #apiFunctionCall << " failed with error: " << _status << "\n\n";         \
                                                                                    \
        exit(EXIT_FAILURE);                                                         \
    }                                                                               \
} while (0)
#endif

#ifndef MEMORY_ALLOCATION_CALL
#define MEMORY_ALLOCATION_CALL(variable)                                            \
do                                                                                  \
{                                                                                   \
    if (variable == NULL)                                                           \
    {                                                                               \
        std::cerr << "\n\nError: " << __FILE__ << ":" << __LINE__ <<                \
        " Memory allocation failed.\n\n";                                           \
                                                                                    \
        exit(EXIT_FAILURE);                                                         \
    }                                                                               \
} while (0)
#endif

#ifndef CHECK_CONDITION
#define CHECK_CONDITION(condition)                                                  \
do                                                                                  \
{                                                                                   \
    if (!(condition))                                                               \
    {                                                                               \
        std::cerr << "\n\nError: " << __FILE__ << ":" << __LINE__ << ": Condition " \
        << #condition << " failed.\n\n";                                            \
                                                                                    \
        exit(EXIT_FAILURE);                                                         \
    }                                                                               \
} while (0)
#endif

#ifndef CHECK_INTEGER_CONDITION
#define CHECK_INTEGER_CONDITION(argument1, operator, argument2)                     \
do                                                                                  \
{                                                                                   \
    if (!(argument1 operator argument2))                                            \
    {                                                                               \
        std::cerr << "\n\nError: " << __FILE__ << ":" << __LINE__ << ": Condition " \
        << #argument1 << " " << #operator << " " << #argument2 << " fails. " <<     \
        #argument1 << " = " << argument1 << ", " << #argument2 << " = " <<          \
        argument2 << "\n\n";                                                        \
                                                                                    \
        exit(EXIT_FAILURE);                                                         \
    }                                                                               \
} while (0)
#endif

#endif // HELPER_CUPTI_H_

