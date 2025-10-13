// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __PYTHON_STACK_H
#define __PYTHON_STACK_H

#define TASK_COMM_LEN		16
#define MAX_CPU_NR		128
#define MAX_ENTRIES		10240
#define MAX_PID_NR		30
#define MAX_TID_NR		30
#define MAX_STACK_DEPTH		20
#define FUNCTION_NAME_LEN	64
#define FILE_NAME_LEN		128

// Python frame information
struct python_frame {
	char function_name[FUNCTION_NAME_LEN];
	char file_name[FILE_NAME_LEN];
	int line_number;
};

// Python stack trace (up to MAX_STACK_DEPTH frames)
struct python_stack {
	int depth;
	struct python_frame frames[MAX_STACK_DEPTH];
};

struct key_t {
	__u32 pid;
	int user_stack_id;
	int kern_stack_id;
	char name[TASK_COMM_LEN];
	// Add Python stack information
	struct python_stack py_stack;
};

// Python internal structures (CPython 3.8+)
// These are simplified versions of CPython internal structures
// Offsets may vary between Python versions

struct PyObject {
	unsigned long ob_refcnt;
	void *ob_type;
};

struct PyVarObject {
	struct PyObject ob_base;
	unsigned long ob_size;
};

// PyCodeObject structure (simplified)
struct PyCodeObject {
	struct PyObject ob_base;
	int co_argcount;
	int co_posonlyargcount;
	int co_kwonlyargcount;
	int co_nlocals;
	int co_stacksize;
	int co_flags;
	int co_firstlineno;
	struct PyObject *co_code;
	struct PyObject *co_consts;
	struct PyObject *co_names;
	struct PyObject *co_varnames;
	struct PyObject *co_freevars;
	struct PyObject *co_cellvars;
	struct PyObject *co_filename;
	struct PyObject *co_name;
	// ... more fields
};

// PyFrameObject structure (simplified)
struct PyFrameObject {
	struct PyVarObject ob_base;
	struct PyFrameObject *f_back;
	struct PyCodeObject *f_code;
	struct PyObject *f_builtins;
	struct PyObject *f_globals;
	struct PyObject *f_locals;
	struct PyObject **f_valuestack;
	struct PyObject **f_stacktop;
	int f_lasti;
	int f_lineno;
	// ... more fields
};

// PyThreadState structure (simplified)
struct PyThreadState {
	struct PyThreadState *next;
	void *interp;
	struct PyFrameObject *frame;
	// ... more fields
};

// PyStringObject / PyBytesObject (for reading strings)
struct PyBytesObject {
	struct PyVarObject ob_base;
	long ob_shash;
	char ob_sval[1]; // Variable length
};

struct PyUnicodeObject {
	struct PyObject ob_base;
	unsigned long length;
	long hash;
	struct {
		unsigned int interned:2;
		unsigned int kind:3;
		unsigned int compact:1;
		unsigned int ascii:1;
		unsigned int ready:1;
	} state;
	void *data; // Pointer to actual string data
};

#endif /* __PYTHON_STACK_H */
