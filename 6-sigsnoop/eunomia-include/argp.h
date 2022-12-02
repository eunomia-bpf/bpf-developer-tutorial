#ifndef EUNOMIA_ARGP_H
#define EUNOMIA_ARGP_H

/* Hierarchial argument parsing.
   Copyright (C) 1995, 96, 97, 98, 99, 2003 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Written by Miles Bader <miles@gnu.ai.mit.edu>.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifndef _ARGP_H
#define _ARGP_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "errno-base.h"
#include <errno.h>

#ifndef __THROW
# define __THROW
#endif

#ifndef __const
# define __const const
#endif

#ifndef __error_t_defined
typedef int error_t;
# define __error_t_defined
#endif

/* FIXME: What's the right way to check for __restrict? Sun's cc seems
   not to have it. Perhaps it's easiest to just delete the use of
   __restrict from the prototypes. */
#ifndef __restrict
# ifndef __GNUC___
#  define __restrict
# endif
#endif

/* NOTE: We can't use the autoconf tests, since this is supposed to be
   an installed header file and argp's config.h is of course not
   installed. */
#ifndef PRINTF_STYLE
# if __GNUC__ >= 2
#  define PRINTF_STYLE(f, a) __attribute__ ((__format__ (__printf__, f, a)))
# else
#  define PRINTF_STYLE(f, a)
# endif
#endif


#define assert(expr) ((void)(expr))

#ifdef  __cplusplus
extern "C" {
#endif

/* A description of a particular option.  A pointer to an array of
   these is passed in the OPTIONS field of an argp structure.  Each option
   entry can correspond to one long option and/or one short option; more
   names for the same option can be added by following an entry in an option
   array with options having the OPTION_ALIAS flag set.  */
struct argp_option
{
  /* The long option name.  For more than one name for the same option, you
     can use following options with the OPTION_ALIAS flag set.  */
  __const char *name;

  /* What key is returned for this option.  If > 0 and printable, then it's
     also accepted as a short option.  */
  int key;

  /* If non-NULL, this is the name of the argument associated with this
     option, which is required unless the OPTION_ARG_OPTIONAL flag is set. */
  __const char *arg;

  /* OPTION_ flags.  */
  int flags;

  /* The doc string for this option.  If both NAME and KEY are 0, This string
     will be printed outdented from the normal option column, making it
     useful as a group header (it will be the first thing printed in its
     group); in this usage, it's conventional to end the string with a `:'.  */
  __const char *doc;

  /* The group this option is in.  In a long help message, options are sorted
     alphabetically within each group, and the groups presented in the order
     0, 1, 2, ..., n, -m, ..., -2, -1.  Every entry in an options array with
     if this field 0 will inherit the group number of the previous entry, or
     zero if it's the first one, unless its a group header (NAME and KEY both
     0), in which case, the previous entry + 1 is the default.  Automagic
     options such as --help are put into group -1.  */
  int group;
};

/* The argument associated with this option is optional.  */
#define OPTION_ARG_OPTIONAL	0x1

/* This option isn't displayed in any help messages.  */
#define OPTION_HIDDEN	       	0x2

/* This option is an alias for the closest previous non-alias option.  This
   means that it will be displayed in the same help entry, and will inherit
   fields other than NAME and KEY from the aliased option.  */
#define OPTION_ALIAS		0x4

/* This option isn't actually an option (and so should be ignored by the
   actual option parser), but rather an arbitrary piece of documentation that
   should be displayed in much the same manner as the options.  If this flag
   is set, then the option NAME field is displayed unmodified (e.g., no `--'
   prefix is added) at the left-margin (where a *short* option would normally
   be displayed), and the documentation string in the normal place.  For
   purposes of sorting, any leading whitespace and puncuation is ignored,
   except that if the first non-whitespace character is not `-', this entry
   is displayed after all options (and OPTION_DOC entries with a leading `-')
   in the same group.  */
#define OPTION_DOC		0x8

/* This option shouldn't be included in `long' usage messages (but is still
   included in help messages).  This is mainly intended for options that are
   completely documented in an argp's ARGS_DOC field, in which case including
   the option in the generic usage list would be redundant.  For instance,
   if ARGS_DOC is "FOO BAR\n-x BLAH", and the `-x' option's purpose is to
   distinguish these two cases, -x should probably be marked
   OPTION_NO_USAGE.  */
#define OPTION_NO_USAGE		0x10

struct argp;			/* fwd declare this type */
struct argp_state;		/* " */
struct argp_child;		/* " */

/* The type of a pointer to an argp parsing function.  */
typedef error_t (*argp_parser_t) (int key, char *arg,
				  struct argp_state *state);

/* What to return for unrecognized keys.  For special ARGP_KEY_ keys, such
   returns will simply be ignored.  For user keys, this error will be turned
   into EINVAL (if the call to argp_parse is such that errors are propagated
   back to the user instead of exiting); returning EINVAL itself would result
   in an immediate stop to parsing in *all* cases.  */
#define ARGP_ERR_UNKNOWN	E2BIG /* Hurd should never need E2BIG.  XXX */

/* Special values for the KEY argument to an argument parsing function.
   ARGP_ERR_UNKNOWN should be returned if they aren't understood.

   The sequence of keys to a parsing function is either (where each
   uppercased word should be prefixed by `ARGP_KEY_' and opt is a user key):

       INIT opt... NO_ARGS END SUCCESS  -- No non-option arguments at all
   or  INIT (opt | ARG)... END SUCCESS  -- All non-option args parsed
   or  INIT (opt | ARG)... SUCCESS      -- Some non-option arg unrecognized

   The third case is where every parser returned ARGP_KEY_UNKNOWN for an
   argument, in which case parsing stops at that argument (returning the
   unparsed arguments to the caller of argp_parse if requested, or stopping
   with an error message if not).

   If an error occurs (either detected by argp, or because the parsing
   function returned an error value), then the parser is called with
   ARGP_KEY_ERROR, and no further calls are made.  */

/* This is not an option at all, but rather a command line argument.  If a
   parser receiving this key returns success, the fact is recorded, and the
   ARGP_KEY_NO_ARGS case won't be used.  HOWEVER, if while processing the
   argument, a parser function decrements the NEXT field of the state it's
   passed, the option won't be considered processed; this is to allow you to
   actually modify the argument (perhaps into an option), and have it
   processed again.  */
#define ARGP_KEY_ARG		0
/* There are remaining arguments not parsed by any parser, which may be found
   starting at (STATE->argv + STATE->next).  If success is returned, but
   STATE->next left untouched, it's assumed that all arguments were consume,
   otherwise, the parser should adjust STATE->next to reflect any arguments
   consumed.  */
#define ARGP_KEY_ARGS		0x1000006
/* There are no more command line arguments at all.  */
#define ARGP_KEY_END		0x1000001
/* Because it's common to want to do some special processing if there aren't
   any non-option args, user parsers are called with this key if they didn't
   successfully process any non-option arguments.  Called just before
   ARGP_KEY_END (where more general validity checks on previously parsed
   arguments can take place).  */
#define ARGP_KEY_NO_ARGS	0x1000002
/* Passed in before any parsing is done.  Afterwards, the values of each
   element of the CHILD_INPUT field, if any, in the state structure is
   copied to each child's state to be the initial value of the INPUT field.  */
#define ARGP_KEY_INIT		0x1000003
/* Use after all other keys, including SUCCESS & END.  */
#define ARGP_KEY_FINI		0x1000007
/* Passed in when parsing has successfully been completed (even if there are
   still arguments remaining).  */
#define ARGP_KEY_SUCCESS	0x1000004
/* Passed in if an error occurs.  */
#define ARGP_KEY_ERROR		0x1000005

/* An argp structure contains a set of options declarations, a function to
   deal with parsing one, documentation string, a possible vector of child
   argp's, and perhaps a function to filter help output.  When actually
   parsing options, getopt is called with the union of all the argp
   structures chained together through their CHILD pointers, with conflicts
   being resolved in favor of the first occurrence in the chain.  */
struct argp
{
  /* An array of argp_option structures, terminated by an entry with both
     NAME and KEY having a value of 0.  */
  __const struct argp_option *options;

  /* What to do with an option from this structure.  KEY is the key
     associated with the option, and ARG is any associated argument (NULL if
     none was supplied).  If KEY isn't understood, ARGP_ERR_UNKNOWN should be
     returned.  If a non-zero, non-ARGP_ERR_UNKNOWN value is returned, then
     parsing is stopped immediately, and that value is returned from
     argp_parse().  For special (non-user-supplied) values of KEY, see the
     ARGP_KEY_ definitions below.  */
  argp_parser_t parser;

  /* A string describing what other arguments are wanted by this program.  It
     is only used by argp_usage to print the `Usage:' message.  If it
     contains newlines, the strings separated by them are considered
     alternative usage patterns, and printed on separate lines (lines after
     the first are prefix by `  or: ' instead of `Usage:').  */
  __const char *args_doc;

  /* If non-NULL, a string containing extra text to be printed before and
     after the options in a long help message (separated by a vertical tab
     `\v' character).  */
  __const char *doc;

  /* A vector of argp_children structures, terminated by a member with a 0
     argp field, pointing to child argps should be parsed with this one.  Any
     conflicts are resolved in favor of this argp, or early argps in the
     CHILDREN list.  This field is useful if you use libraries that supply
     their own argp structure, which you want to use in conjunction with your
     own.  */
  __const struct argp_child *children;

  /* If non-zero, this should be a function to filter the output of help
     messages.  KEY is either a key from an option, in which case TEXT is
     that option's help text, or a special key from the ARGP_KEY_HELP_
     defines, below, describing which other help text TEXT is.  The function
     should return either TEXT, if it should be used as-is, a replacement
     string, which should be malloced, and will be freed by argp, or NULL,
     meaning `print nothing'.  The value for TEXT is *after* any translation
     has been done, so if any of the replacement text also needs translation,
     that should be done by the filter function.  INPUT is either the input
     supplied to argp_parse, or NULL, if argp_help was called directly.  */
  char *(*help_filter) (int __key, __const char *__text, void *__input);

  /* If non-zero the strings used in the argp library are translated using
     the domain described by this string.  Otherwise the currently installed
     default domain is used.  */
  const char *argp_domain;
};

/* Possible KEY arguments to a help filter function.  */
#define ARGP_KEY_HELP_PRE_DOC	0x2000001 /* Help text preceeding options. */
#define ARGP_KEY_HELP_POST_DOC	0x2000002 /* Help text following options. */
#define ARGP_KEY_HELP_HEADER	0x2000003 /* Option header string. */
#define ARGP_KEY_HELP_EXTRA	0x2000004 /* After all other documentation;
					     TEXT is NULL for this key.  */
/* Explanatory note emitted when duplicate option arguments have been
   suppressed.  */
#define ARGP_KEY_HELP_DUP_ARGS_NOTE 0x2000005
#define ARGP_KEY_HELP_ARGS_DOC	0x2000006 /* Argument doc string.  */

/* When an argp has a non-zero CHILDREN field, it should point to a vector of
   argp_child structures, each of which describes a subsidiary argp.  */
struct argp_child
{
  /* The child parser.  */
  __const struct argp *argp;

  /* Flags for this child.  */
  int flags;

  /* If non-zero, an optional header to be printed in help output before the
     child options.  As a side-effect, a non-zero value forces the child
     options to be grouped together; to achieve this effect without actually
     printing a header string, use a value of "".  */
  __const char *header;

  /* Where to group the child options relative to the other (`consolidated')
     options in the parent argp; the values are the same as the GROUP field
     in argp_option structs, but all child-groupings follow parent options at
     a particular group level.  If both this field and HEADER are zero, then
     they aren't grouped at all, but rather merged with the parent options
     (merging the child's grouping levels with the parents).  */
  int group;
};

/* Parsing state.  This is provided to parsing functions called by argp,
   which may examine and, as noted, modify fields.  */
struct argp_state
{
  /* The top level ARGP being parsed.  */
  __const struct argp *root_argp;

  /* The argument vector being parsed.  May be modified.  */
  int argc;
  char **argv;

  /* The index in ARGV of the next arg that to be parsed.  May be modified. */
  int next;

  /* The flags supplied to argp_parse.  May be modified.  */
  unsigned flags;

  /* While calling a parsing function with a key of ARGP_KEY_ARG, this is the
     number of the current arg, starting at zero, and incremented after each
     such call returns.  At all other times, this is the number of such
     arguments that have been processed.  */
  unsigned arg_num;

  /* If non-zero, the index in ARGV of the first argument following a special
     `--' argument (which prevents anything following being interpreted as an
     option).  Only set once argument parsing has proceeded past this point. */
  int quoted;

  /* An arbitrary pointer passed in from the user.  */
  void *input;
  /* Values to pass to child parsers.  This vector will be the same length as
     the number of children for the current parser.  */
  void **child_inputs;

  /* For the parser's use.  Initialized to 0.  */
  void *hook;

  /* The name used when printing messages.  This is initialized to ARGV[0],
     or PROGRAM_INVOCATION_NAME if that is unavailable.  */
  char *name;

  void *pstate;			/* Private, for use by argp.  */
};

/* Flags for argp_parse (note that the defaults are those that are
   convenient for program command line parsing): */

/* Don't ignore the first element of ARGV.  Normally (and always unless
   ARGP_NO_ERRS is set) the first element of the argument vector is
   skipped for option parsing purposes, as it corresponds to the program name
   in a command line.  */
#define ARGP_PARSE_ARGV0  0x01

/* Don't print error messages for unknown options to stderr; unless this flag
   is set, ARGP_PARSE_ARGV0 is ignored, as ARGV[0] is used as the program
   name in the error messages.  This flag implies ARGP_NO_EXIT (on the
   assumption that silent exiting upon errors is bad behaviour).  */
#define ARGP_NO_ERRS	0x02

/* Don't parse any non-option args.  Normally non-option args are parsed by
   calling the parse functions with a key of ARGP_KEY_ARG, and the actual arg
   as the value.  Since it's impossible to know which parse function wants to
   handle it, each one is called in turn, until one returns 0 or an error
   other than ARGP_ERR_UNKNOWN; if an argument is handled by no one, the
   argp_parse returns prematurely (but with a return value of 0).  If all
   args have been parsed without error, all parsing functions are called one
   last time with a key of ARGP_KEY_END.  This flag needn't normally be set,
   as the normal behavior is to stop parsing as soon as some argument can't
   be handled.  */
#define ARGP_NO_ARGS	0x04

/* Parse options and arguments in the same order they occur on the command
   line -- normally they're rearranged so that all options come first. */
#define ARGP_IN_ORDER	0x08

/* Don't provide the standard long option --help, which causes usage and
      option help information to be output to stdout, and exit (0) called. */
#define ARGP_NO_HELP	0x10

/* Don't exit on errors (they may still result in error messages).  */
#define ARGP_NO_EXIT	0x20

/* Use the gnu getopt `long-only' rules for parsing arguments.  */
#define ARGP_LONG_ONLY	0x40

/* Turns off any message-printing/exiting options.  */
#define ARGP_SILENT    (ARGP_NO_EXIT | ARGP_NO_ERRS | ARGP_NO_HELP)

/* Parse the options strings in ARGC & ARGV according to the options in ARGP.
   FLAGS is one of the ARGP_ flags above.  If ARG_INDEX is non-NULL, the
   index in ARGV of the first unparsed option is returned in it.  If an
   unknown option is present, ARGP_ERR_UNKNOWN is returned; if some parser
   routine returned a non-zero value, it is returned; otherwise 0 is
   returned.  This function may also call exit unless the ARGP_NO_HELP flag
   is set.  INPUT is a pointer to a value to be passed in to the parser.  */
extern error_t argp_parse (__const struct argp *__restrict argp,
			   int argc, char **__restrict argv,
			   unsigned flags, int *__restrict arg_index,
			   void *__restrict input) __THROW;
extern error_t __argp_parse (__const struct argp *__restrict argp,
			     int argc, char **__restrict argv,
			     unsigned flags, int *__restrict arg_index,
			     void *__restrict input) __THROW;

/* Global variables.  */

/* If defined or set by the user program to a non-zero value, then a default
   option --version is added (unless the ARGP_NO_HELP flag is used), which
   will print this string followed by a newline and exit (unless the
   ARGP_NO_EXIT flag is used).  Overridden by ARGP_PROGRAM_VERSION_HOOK.  */
extern __const char *argp_program_version;

/* If defined or set by the user program to a non-zero value, then a default
   option --version is added (unless the ARGP_NO_HELP flag is used), which
   calls this function with a stream to print the version to and a pointer to
   the current parsing state, and then exits (unless the ARGP_NO_EXIT flag is
   used).  This variable takes precedent over ARGP_PROGRAM_VERSION.  */
extern void (*argp_program_version_hook) (
					  struct argp_state *__restrict
					  __state);

/* If defined or set by the user program, it should point to string that is
   the bug-reporting address for the program.  It will be printed by
   argp_help if the ARGP_HELP_BUG_ADDR flag is set (as it is by various
   standard help messages), embedded in a sentence that says something like
   `Report bugs to ADDR.'.  */
extern __const char *argp_program_bug_address;

/* The exit status that argp will use when exiting due to a parsing error.
   If not defined or set by the user program, this defaults to EX_USAGE from
   <sysexits.h>.  */
extern error_t argp_err_exit_status;

/* Flags for argp_help.  */
#define ARGP_HELP_USAGE		0x01 /* a Usage: message. */
#define ARGP_HELP_SHORT_USAGE	0x02 /*  " but don't actually print options. */
#define ARGP_HELP_SEE		0x04 /* a `Try ... for more help' message. */
#define ARGP_HELP_LONG		0x08 /* a long help message. */
#define ARGP_HELP_PRE_DOC	0x10 /* doc string preceding long help.  */
#define ARGP_HELP_POST_DOC	0x20 /* doc string following long help.  */
#define ARGP_HELP_DOC		(ARGP_HELP_PRE_DOC | ARGP_HELP_POST_DOC)
#define ARGP_HELP_BUG_ADDR	0x40 /* bug report address */
#define ARGP_HELP_LONG_ONLY	0x80 /* modify output appropriately to
					reflect ARGP_LONG_ONLY mode.  */

/* These ARGP_HELP flags are only understood by argp_state_help.  */
#define ARGP_HELP_EXIT_ERR	0x100 /* Call exit(1) instead of returning.  */
#define ARGP_HELP_EXIT_OK	0x200 /* Call exit(0) instead of returning.  */

/* The standard thing to do after a program command line parsing error, if an
   error message has already been printed.  */
#define ARGP_HELP_STD_ERR \
  (ARGP_HELP_SEE | ARGP_HELP_EXIT_ERR)
/* The standard thing to do after a program command line parsing error, if no
   more specific error message has been printed.  */
#define ARGP_HELP_STD_USAGE \
  (ARGP_HELP_SHORT_USAGE | ARGP_HELP_SEE | ARGP_HELP_EXIT_ERR)
/* The standard thing to do in response to a --help option.  */
#define ARGP_HELP_STD_HELP \
  (ARGP_HELP_SHORT_USAGE | ARGP_HELP_LONG | ARGP_HELP_EXIT_OK \
   | ARGP_HELP_DOC | ARGP_HELP_BUG_ADDR)


/* Possibly output the standard usage message for ARGP to stderr and exit.  */
extern void argp_usage (__const struct argp_state *__state) __THROW;
extern void __argp_usage (__const struct argp_state *__state) __THROW;

/* If appropriate, print the printf string FMT and following args, preceded
   by the program name and `:', to stderr, and followed by a `Try ... --help'
   message, then exit (1).  */
extern void argp_error (__const struct argp_state *__restrict __state,
			__const char *__restrict __fmt, ...) __THROW
     PRINTF_STYLE(2,3);
extern void __argp_error (__const struct argp_state *__restrict __state,
			  __const char *__restrict __fmt, ...) __THROW
     PRINTF_STYLE(2,3);

/* Returns true if the option OPT is a valid short option.  */
extern int _option_is_short (__const struct argp_option *__opt) __THROW;
extern int __option_is_short (__const struct argp_option *__opt) __THROW;

/* Returns true if the option OPT is in fact the last (unused) entry in an
   options array.  */
extern int _option_is_end (__const struct argp_option *__opt) __THROW;
extern int __option_is_end (__const struct argp_option *__opt) __THROW;

/* Return the input field for ARGP in the parser corresponding to STATE; used
   by the help routines.  */
extern void *_argp_input (__const struct argp *__restrict __argp,
			  __const struct argp_state *__restrict __state)
     __THROW;
extern void *__argp_input (__const struct argp *__restrict __argp,
			   __const struct argp_state *__restrict __state)
     __THROW;

/* Used for extracting the program name from argv[0] */
extern char *_argp_basename(char *name) __THROW;
extern char *__argp_basename(char *name) __THROW;

/* Getting the program name given an argp state */
extern char *
_argp_short_program_name(const struct argp_state *state) __THROW;
extern char *
__argp_short_program_name(const struct argp_state *state) __THROW;


#ifdef __USE_EXTERN_INLINES

# if !_LIBC
#  define __argp_usage argp_usage
#  define __argp_state_help argp_state_help
#  define __option_is_short _option_is_short
#  define __option_is_end _option_is_end
# endif

# ifndef ARGP_EI
#  define ARGP_EI extern __inline__
# endif

ARGP_EI void
__argp_usage (__const struct argp_state *__state)
{
  __argp_state_help (__state, stderr, ARGP_HELP_STD_USAGE);
}

ARGP_EI int
__option_is_short (__const struct argp_option *__opt)
{
  if (__opt->flags & OPTION_DOC)
    return 0;
  else
    {
      int __key = __opt->key;
      return __key > 0 && isprint (__key);
    }
}

ARGP_EI int
__option_is_end (__const struct argp_option *__opt)
{
  return !__opt->key && !__opt->name && !__opt->doc && !__opt->group;
}

# if !_LIBC
#  undef __argp_usage
#  undef __argp_state_help
#  undef __option_is_short
#  undef __option_is_end
# endif
#endif /* Use extern inlines.  */

#ifdef  __cplusplus
}
#endif

#endif /* argp.h */


#ifndef _GNU_SOURCE
# define _GNU_SOURCE	1
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* AIX requires this to be the first thing in the file.  */
#ifndef __GNUC__
# if HAVE_ALLOCA_H
#  include <alloca.h>
# else
#  ifdef _AIX
 #pragma alloca
#  else
#   ifndef alloca /* predefined by HP cc +Olibcalls */
char *alloca ();
#   endif
#  endif
# endif
#endif

#include <stdlib.h>
#include <string.h>
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <limits.h>
#include <assert.h>

#if HAVE_MALLOC_H
/* Needed, for alloca on windows */
# include <malloc.h>
#endif

#ifndef _
/* This is for other GNU distributions with internationalized messages.
   When compiling libc, the _ macro is predefined.  */
# if defined HAVE_LIBINTL_H || defined _LIBC
#  include <libintl.h>
#  ifdef _LIBC
#   undef dgettext
#   define dgettext(domain, msgid) __dcgettext (domain, msgid, LC_MESSAGES)
#  endif
# else
#  define dgettext(domain, msgid) (msgid)
#  define gettext(msgid) (msgid)
# endif
#endif
#ifndef N_
# define N_(msgid) (msgid)
#endif

#if _LIBC - 0
#include <bits/libc-lock.h>
#else
#ifdef HAVE_CTHREADS_H
#include <cthreads.h>
#endif
#endif /* _LIBC */

#include "argp.h"




/* The meta-argument used to prevent any further arguments being interpreted
   as options.  */
#define QUOTE "--"

/* EZ alias for ARGP_ERR_UNKNOWN.  */
#define EBADKEY ARGP_ERR_UNKNOWN


/* Default options.  */

/* When argp is given the --HANG switch, _ARGP_HANG is set and argp will sleep
   for one second intervals, decrementing _ARGP_HANG until it's zero.  Thus
   you can force the program to continue by attaching a debugger and setting
   it to 0 yourself.  */
volatile int _argp_hang;

#define OPT_PROGNAME	-2
#define OPT_USAGE	-3
#if HAVE_SLEEP && HAVE_GETPID
#define OPT_HANG	-4
#endif

static const struct argp_option argp_default_options[] =
{
  {"help",	  '?',    	0, 0,  N_("Give this help list"), -1},
  {"usage",	  OPT_USAGE,	0, 0,  N_("Give a short usage message"), 0 },
  {"program-name",OPT_PROGNAME,"NAME", OPTION_HIDDEN,
     N_("Set the program name"), 0},
#if OPT_HANG
  {"HANG",	  OPT_HANG,    "SECS", OPTION_ARG_OPTIONAL | OPTION_HIDDEN,
     N_("Hang for SECS seconds (default 3600)"), 0 },
#endif
  {0, 0, 0, 0, 0, 0}
};

static error_t
argp_default_parser (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case '?':
    //   __argp_state_help (state,  ARGP_HELP_STD_HELP);
      break;
    case OPT_USAGE:
    //   __argp_state_help (state, 
	// 	       ARGP_HELP_USAGE | ARGP_HELP_EXIT_OK);
      break;

    case OPT_PROGNAME:		/* Set the program name.  */
#if HAVE_DECL_PROGRAM_INVOCATION_NAME
      program_invocation_name = arg;
#endif
      /* [Note that some systems only have PROGRAM_INVOCATION_SHORT_NAME (aka
	 __PROGNAME), in which case, PROGRAM_INVOCATION_NAME is just defined
	 to be that, so we have to be a bit careful here.]  */

      /* Update what we use for messages.  */

      state->name = arg;
      
#if HAVE_DECL_PROGRAM_INVOCATION_SHORT_NAME
      program_invocation_short_name = state->name;
#endif

      if ((state->flags & (ARGP_PARSE_ARGV0 | ARGP_NO_ERRS))
	  == ARGP_PARSE_ARGV0)
	/* Update what getopt uses too.  */
	state->argv[0] = arg;

      break;
      
#if OPT_HANG
    case OPT_HANG:
      _argp_hang = atoi (arg ? arg : "3600");
      printf( "%s: pid = %ld\n",
	      state->name, (long) getpid());
      while (_argp_hang-- > 0)
	__sleep (1);
      break;
#endif
      
    default:
      return EBADKEY;
    }
  return 0;
}

static const struct argp argp_default_argp =
  {argp_default_options, &argp_default_parser, NULL, NULL, NULL, NULL, "libc"};


static const struct argp_option argp_version_options[] =
{
  {"version",	  'V',    	0, 0,  N_("Print program version"), -1},
  {0, 0, 0, 0, 0, 0 }
};

static error_t
argp_version_parser (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'V':
      if (argp_program_version_hook)
	(*argp_program_version_hook) (state);
      else if (argp_program_version)
	printf ("%s\n", argp_program_version);
      else;
	// __argp_error (state, dgettext (state->root_argp->argp_domain,
	// 			       "(PROGRAM ERROR) No version known!?"));
      if (! (state->flags & ARGP_NO_EXIT))
	exit (0);
      break;
    default:
      return EBADKEY;
    }
  return 0;
}

static const struct argp argp_version_argp =
  {argp_version_options, &argp_version_parser, NULL, NULL, NULL, NULL, "libc"};



/* The state of a `group' during parsing.  Each group corresponds to a
   particular argp structure from the tree of such descending from the top
   level argp passed to argp_parse.  */
struct group
{
  /* This group's parsing function.  */
  argp_parser_t parser;

  /* Which argp this group is from.  */
  const struct argp *argp;

  /* The number of non-option args sucessfully handled by this parser.  */
  unsigned args_processed;

  /* This group's parser's parent's group.  */
  struct group *parent;
  unsigned parent_index;	/* And the our position in the parent.   */

  /* These fields are swapped into and out of the state structure when
     calling this group's parser.  */
  void *input, **child_inputs;
  void *hook;
};

/* Call GROUP's parser with KEY and ARG, swapping any group-specific info
   from STATE before calling, and back into state afterwards.  If GROUP has
   no parser, EBADKEY is returned.  */
static error_t
group_parse (struct group *group, struct argp_state *state, int key, char *arg)
{
  if (group->parser)
    {
      error_t err;
      state->hook = group->hook;
      state->input = group->input;
      state->child_inputs = group->child_inputs;
      state->arg_num = group->args_processed;
      err = (*group->parser)(key, arg, state);
      group->hook = state->hook;
      return err;
    }
  else
    return EBADKEY;
}

struct parser
{
  const struct argp *argp;

  const char *posixly_correct;
  
  /* True if there are only no-option arguments left, which are just
     passed verbatim with ARGP_KEY_ARG. This is set if we encounter a
     quote, or the end of the proper options, but may be cleared again
     if the user moves the next argument pointer backwards. */
  int args_only;

  /* Describe how to deal with options that follow non-option ARGV-elements.

     If the caller did not specify anything, the default is
     REQUIRE_ORDER if the environment variable POSIXLY_CORRECT is
     defined, PERMUTE otherwise.

     REQUIRE_ORDER means don't recognize them as options; stop option
     processing when the first non-option is seen. This is what Unix
     does. This mode of operation is selected by either setting the
     environment variable POSIXLY_CORRECT, or using `+' as the first
     character of the list of option characters.

     PERMUTE is the default. We permute the contents of ARGV as we
     scan, so that eventually all the non-options are at the end. This
     allows options to be given in any order, even with programs that
     were not written to expect this.

     RETURN_IN_ORDER is an option available to programs that were
     written to expect options and other ARGV-elements in any order
     and that care about the ordering of the two. We describe each
     non-option ARGV-element as if it were the argument of an option
     with character code 1. Using `-' as the first character of the
     list of option characters selects this mode of operation.

  */
  enum { REQUIRE_ORDER, PERMUTE, RETURN_IN_ORDER } ordering;

  /* A segment of non-option arguments that have been skipped for
     later processing, after all options. `first_nonopt' is the index
     in ARGV of the first of them; `last_nonopt' is the index after
     the last of them.

     If quoted or args_only is non-zero, this segment should be empty. */

  /* FIXME: I'd prefer to use unsigned, but it's more consistent to
     use the same type as for state.next. */
  int first_nonopt;
  int last_nonopt;
  
  /* String of all recognized short options. Needed for ARGP_LONG_ONLY. */
  /* FIXME: Perhaps change to a pointer to a suitable bitmap instead? */
  char *short_opts;

  /* For parsing combined short options. */
  char *nextchar;
  
  /* States of the various parsing groups.  */
  struct group *groups;
  /* The end of the GROUPS array.  */
  struct group *egroup;
  /* An vector containing storage for the CHILD_INPUTS field in all groups.  */
  void **child_inputs;
  
  /* State block supplied to parsing routines.  */
  struct argp_state state;

  /* Memory used by this parser.  */
  void *storage;
};

/* Search for a group defining a short option. */
static const struct argp_option *
find_short_option(struct parser *parser, int key, struct group **p)
{
  struct group *group;

  for (group = parser->groups; group < parser->egroup; group++)
    {
      const struct argp_option *opts;

      for (opts = group->argp->options; !__option_is_end(opts); opts++)
	if (opts->key == key)
	  {
	    *p = group;
	    return opts;
	  }
    }
  return NULL;
}

enum match_result { MATCH_EXACT, MATCH_PARTIAL, MATCH_NO };

/* If defined, allow complete.el-like abbreviations of long options. */
#ifndef ARGP_COMPLETE
#define ARGP_COMPLETE 0
#endif

/* Matches an encountern long-option argument ARG against an option NAME.
 * ARG is terminated by NUL or '='. */
static enum match_result
match_option(const char *arg, const char *name)
{
  unsigned i, j;
  for (i = j = 0;; i++, j++)
    {
      switch(arg[i])
	{
	case '\0':
	case '=':
	  return name[j] ? MATCH_PARTIAL : MATCH_EXACT;
#if ARGP_COMPLETE
	case '-':
	  while (name[j] != '-')
	    if (!name[j++])
	      return MATCH_NO;
	  break;
#endif
	default:
	  if (arg[i] != name[j])
	    return MATCH_NO;
	}
    }
}

static const struct argp_option *
find_long_option(struct parser *parser,
		 const char *arg,
		 struct group **p)
{
  struct group *group;

  /* Partial match found so far. */
  struct group *matched_group = NULL;
  const struct argp_option *matched_option = NULL;

  /* Number of partial matches. */
  int num_partial = 0;

  for (group = parser->groups; group < parser->egroup; group++)
    {
      const struct argp_option *opts;

      for (opts = group->argp->options; !__option_is_end(opts); opts++)
	{
	  if (!opts->name)
	    continue;
	  switch (match_option(arg, opts->name))
	    {
	    case MATCH_NO:
	      break;
	    case MATCH_PARTIAL:
	      num_partial++;

	      matched_group = group;
	      matched_option = opts;

	      break;
	    case MATCH_EXACT:
	      /* Exact match. */
	      *p = group;
	      return opts;
	    }
	}
    }
  if (num_partial == 1)
    {
      *p = matched_group;
      return matched_option;
    }

  return NULL;
}


/* The next usable entries in the various parser tables being filled in by
   convert_options.  */
struct parser_convert_state
{
  struct parser *parser;
  char *short_end;
  void **child_inputs_end;
};

/* Initialize GROUP from ARGP. If CVT->SHORT_END is non-NULL, short
   options are recorded in the short options string. Returns the next
   unused group entry. CVT holds state used during the conversion. */
static struct group *
convert_options (const struct argp *argp,
		 struct group *parent, unsigned parent_index,
		 struct group *group, struct parser_convert_state *cvt)
{
  const struct argp_option *opt = argp->options;
  const struct argp_child *children = argp->children;

  if (opt || argp->parser)
    {
      /* This parser needs a group. */
      if (cvt->short_end)
	{
	  /* Record any short options. */
	  for ( ; !__option_is_end (opt); opt++)
	    if (__option_is_short(opt))
	      *cvt->short_end++ = opt->key;
	}
      
      group->parser = argp->parser;
      group->argp = argp;
      group->args_processed = 0;
      group->parent = parent;
      group->parent_index = parent_index;
      group->input = 0;
      group->hook = 0;
      group->child_inputs = 0;
      
      if (children)
	/* Assign GROUP's CHILD_INPUTS field some space from
	   CVT->child_inputs_end.*/
	{
	  unsigned num_children = 0;
	  while (children[num_children].argp)
	    num_children++;
	  group->child_inputs = cvt->child_inputs_end;
	  cvt->child_inputs_end += num_children;
	}
      parent = group++;
    }
  else
    parent = 0;

  if (children)
    {
      unsigned index = 0;
      while (children->argp)
	group =
	  convert_options (children++->argp, parent, index++, group, cvt);
    }

  return group;
}
/* Allocate and initialize the group structures, so that they are
   ordered as if by traversing the corresponding argp parser tree in
   pre-order. Also build the list of short options, if that is needed. */
static void
parser_convert (struct parser *parser, const struct argp *argp)
{
  struct parser_convert_state cvt;

  cvt.parser = parser;
  cvt.short_end = parser->short_opts;
  cvt.child_inputs_end = parser->child_inputs;

  parser->argp = argp;

  if (argp)
    parser->egroup = convert_options (argp, 0, 0, parser->groups, &cvt);
  else
    parser->egroup = parser->groups; /* No parsers at all! */

  if (parser->short_opts)
    *cvt.short_end ='\0';
}

/* Lengths of various parser fields which we will allocated.  */
struct parser_sizes
{
  /* Needed only ARGP_LONG_ONLY */
  size_t short_len;		/* Number of short options.  */

  size_t num_groups;		/* Group structures we allocate.  */
  size_t num_child_inputs;	/* Child input slots.  */
};

/* For ARGP, increments the NUM_GROUPS field in SZS by the total
   number of argp structures descended from it, and the SHORT_LEN by
   the total number of short options. */
static void
calc_sizes (const struct argp *argp,  struct parser_sizes *szs)
{
  const struct argp_child *child = argp->children;
  const struct argp_option *opt = argp->options;

  if (opt || argp->parser)
    {
      /* This parser needs a group. */
      szs->num_groups++;
      if (opt)
	{
	  while (__option_is_short (opt++))
	    szs->short_len++;
	}
    }

  if (child)
    while (child->argp)
      {
	calc_sizes ((child++)->argp, szs);
	szs->num_child_inputs++;
      }
}

/* Initializes PARSER to parse ARGP in a manner described by FLAGS.  */
static error_t
parser_init (struct parser *parser, const struct argp *argp,
	     int argc, char **argv, int flags, void *input)
{
  error_t err = 0;
  struct group *group;
  struct parser_sizes szs;

  if (flags & ARGP_IN_ORDER)
    parser->ordering = RETURN_IN_ORDER;
  else if (flags & ARGP_NO_ARGS)
    parser->ordering = REQUIRE_ORDER;
  else if (parser->posixly_correct)
    parser->ordering = REQUIRE_ORDER;
  else
    parser->ordering = PERMUTE;
  
  szs.short_len = 0;
  szs.num_groups = 0;
  szs.num_child_inputs = 0;

  if (argp)
    calc_sizes (argp, &szs);

  if (!(flags & ARGP_LONG_ONLY))
    /* We have no use for the short option array. */
    szs.short_len = 0;
  
  /* Lengths of the various bits of storage used by PARSER.  */
#define GLEN (szs.num_groups + 1) * sizeof (struct group)
#define CLEN (szs.num_child_inputs * sizeof (void *))
#define SLEN (szs.short_len + 1)
#define STORAGE(offset) ((void *) (((char *) parser->storage) + (offset)))

  parser->storage = malloc (GLEN + CLEN + SLEN);
  if (! parser->storage)
    return ENOMEM;

  parser->groups = parser->storage;

  parser->child_inputs = STORAGE(GLEN);
  memset (parser->child_inputs, 0, szs.num_child_inputs * sizeof (void *));

  if (flags & ARGP_LONG_ONLY)
    parser->short_opts = STORAGE(GLEN + CLEN);
  else
    parser->short_opts = NULL;

  parser_convert (parser, argp);

  memset (&parser->state, 0, sizeof (struct argp_state));
  
  parser->state.root_argp = parser->argp;
  parser->state.argc = argc;
  parser->state.argv = argv;
  parser->state.flags = flags;
  parser->state.pstate = parser;

  parser->args_only = 0;
  parser->nextchar = NULL;
  parser->first_nonopt = parser->last_nonopt = 0;
    
  /* Call each parser for the first time, giving it a chance to propagate
     values to child parsers.  */
  if (parser->groups < parser->egroup)
    parser->groups->input = input;
  for (group = parser->groups;
       group < parser->egroup && (!err || err == EBADKEY);
       group++)
    {
      if (group->parent)
	/* If a child parser, get the initial input value from the parent. */
	group->input = group->parent->child_inputs[group->parent_index];

      if (!group->parser
	  && group->argp->children && group->argp->children->argp)
	/* For the special case where no parsing function is supplied for an
	   argp, propagate its input to its first child, if any (this just
	   makes very simple wrapper argps more convenient).  */
	group->child_inputs[0] = group->input;

      err = group_parse (group, &parser->state, ARGP_KEY_INIT, 0);
    }
  if (err == EBADKEY)
    err = 0;			/* Some parser didn't understand.  */

  if (err)
    return err;

  if (argv[0] && !(parser->state.flags & ARGP_PARSE_ARGV0))
    /* There's an argv[0]; use it for messages.  */
    {
      parser->state.name = argv[0];

      /* Don't parse it as an argument. */
      parser->state.next = 1;
    }
  else
    parser->state.name =  "";
  
  return 0;
}

/* Free any storage consumed by PARSER (but not PARSER itself).  */
static error_t
parser_finalize (struct parser *parser,
		 error_t err, int arg_ebadkey, int *end_index)
{
  struct group *group;

  if (err == EBADKEY && arg_ebadkey)
    /* Suppress errors generated by unparsed arguments.  */
    err = 0;

  if (! err)
    {
      if (parser->state.next == parser->state.argc)
	/* We successfully parsed all arguments!  Call all the parsers again,
	   just a few more times... */
	{
	  for (group = parser->groups;
	       group < parser->egroup && (!err || err==EBADKEY);
	       group++)
	    if (group->args_processed == 0)
	      err = group_parse (group, &parser->state, ARGP_KEY_NO_ARGS, 0);
	  for (group = parser->egroup - 1;
	       group >= parser->groups && (!err || err==EBADKEY);
	       group--)
	    err = group_parse (group, &parser->state, ARGP_KEY_END, 0);

	  if (err == EBADKEY)
	    err = 0;		/* Some parser didn't understand.  */

	  /* Tell the user that all arguments are parsed.  */
	  if (end_index)
	    *end_index = parser->state.next;
	}
      else if (end_index)
	/* Return any remaining arguments to the user.  */
	*end_index = parser->state.next;
      else
	/* No way to return the remaining arguments, they must be bogus. */
	{
	  if (!(parser->state.flags & ARGP_NO_ERRS))
	    printf(
		     dgettext (parser->argp->argp_domain,
			       "%s: Too many arguments\n"),
		     parser->state.name);
	  err = EBADKEY;
	}
    }

  /* Okay, we're all done, with either an error or success; call the parsers
     to indicate which one.  */

  if (err)
    {
      /* Maybe print an error message.  */
      if (err == EBADKEY)
	/* An appropriate message describing what the error was should have
	   been printed earlier.  */
	// __argp_state_help (&parser->state, 
	// 		   ARGP_HELP_STD_ERR);

      /* Since we didn't exit, give each parser an error indication.  */
      for (group = parser->groups; group < parser->egroup; group++)
	group_parse (group, &parser->state, ARGP_KEY_ERROR, 0);
    }
  else
    /* Notify parsers of success, and propagate back values from parsers.  */
    {
      /* We pass over the groups in reverse order so that child groups are
	 given a chance to do there processing before passing back a value to
	 the parent.  */
      for (group = parser->egroup - 1
	   ; group >= parser->groups && (!err || err == EBADKEY)
	   ; group--)
	err = group_parse (group, &parser->state, ARGP_KEY_SUCCESS, 0);
      if (err == EBADKEY)
	err = 0;		/* Some parser didn't understand.  */
    }

  /* Call parsers once more, to do any final cleanup.  Errors are ignored.  */
  for (group = parser->egroup - 1; group >= parser->groups; group--)
    group_parse (group, &parser->state, ARGP_KEY_FINI, 0);

  if (err == EBADKEY)
    err = EINVAL;

  free (parser->storage);

  return err;
}

/* Call the user parsers to parse the non-option argument VAL, at the
   current position, returning any error. The state NEXT pointer
   should point to the argument; this function will adjust it
   correctly to reflect however many args actually end up being
   consumed. */
static error_t
parser_parse_arg (struct parser *parser, char *val)
{
  /* Save the starting value of NEXT */
  int index = parser->state.next;
  error_t err = EBADKEY;
  struct group *group;
  int key = 0;			/* Which of ARGP_KEY_ARG[S] we used.  */

  /* Try to parse the argument in each parser.  */
  for (group = parser->groups
       ; group < parser->egroup && err == EBADKEY
       ; group++)
    {
      parser->state.next++;	/* For ARGP_KEY_ARG, consume the arg.  */
      key = ARGP_KEY_ARG;
      err = group_parse (group, &parser->state, key, val);

      if (err == EBADKEY)
	/* This parser doesn't like ARGP_KEY_ARG; try ARGP_KEY_ARGS instead. */
	{
	  parser->state.next--;	/* For ARGP_KEY_ARGS, put back the arg.  */
	  key = ARGP_KEY_ARGS;
	  err = group_parse (group, &parser->state, key, 0);
	}
    }

  if (! err)
    {
      if (key == ARGP_KEY_ARGS)
	/* The default for ARGP_KEY_ARGS is to assume that if NEXT isn't
	   changed by the user, *all* arguments should be considered
	   consumed.  */
	parser->state.next = parser->state.argc;

      if (parser->state.next > index)
	/* Remember that we successfully processed a non-option
	   argument -- but only if the user hasn't gotten tricky and set
	   the clock back.  */
	(--group)->args_processed += (parser->state.next - index);
      else
	/* The user wants to reparse some args, so try looking for options again.  */
	parser->args_only = 0;
    }

  return err;
}

/* Exchange two adjacent subsequences of ARGV.
   One subsequence is elements [first_nonopt,last_nonopt)
   which contains all the non-options that have been skipped so far.
   The other is elements [last_nonopt,next), which contains all
   the options processed since those non-options were skipped.

   `first_nonopt' and `last_nonopt' are relocated so that they describe
   the new indices of the non-options in ARGV after they are moved.  */

static void
exchange (struct parser *parser)
{
  int bottom = parser->first_nonopt;
  int middle = parser->last_nonopt;
  int top = parser->state.next;
  char **argv = parser->state.argv;
  
  char *tem;

  /* Exchange the shorter segment with the far end of the longer segment.
     That puts the shorter segment into the right place.
     It leaves the longer segment in the right place overall,
     but it consists of two parts that need to be swapped next.  */

  while (top > middle && middle > bottom)
    {
      if (top - middle > middle - bottom)
	{
	  /* Bottom segment is the short one.  */
	  int len = middle - bottom;
	  register int i;

	  /* Swap it with the top part of the top segment.  */
	  for (i = 0; i < len; i++)
	    {
	      tem = argv[bottom + i];
	      argv[bottom + i] = argv[top - (middle - bottom) + i];
	      argv[top - (middle - bottom) + i] = tem;
	    }
	  /* Exclude the moved bottom segment from further swapping.  */
	  top -= len;
	}
      else
	{
	  /* Top segment is the short one.  */
	  int len = top - middle;
	  register int i;

	  /* Swap it with the bottom part of the bottom segment.  */
	  for (i = 0; i < len; i++)
	    {
	      tem = argv[bottom + i];
	      argv[bottom + i] = argv[middle + i];
	      argv[middle + i] = tem;
	    }
	  /* Exclude the moved top segment from further swapping.  */
	  bottom += len;
	}
    }

  /* Update records for the slots the non-options now occupy.  */

  parser->first_nonopt += (parser->state.next - parser->last_nonopt);
  parser->last_nonopt = parser->state.next;
}


enum arg_type { ARG_ARG, ARG_SHORT_OPTION,
		ARG_LONG_OPTION, ARG_LONG_ONLY_OPTION,
		ARG_QUOTE };

static enum arg_type
classify_arg(struct parser *parser, char *arg, char **opt)
{
  if (arg[0] == '-')
    /* Looks like an option... */
    switch (arg[1])
      {
      case '\0':
	/* "-" is not an option. */
	return ARG_ARG;
      case '-':
	/* Long option, or quote. */
	if (!arg[2])
	  return ARG_QUOTE;
	  
	/* A long option. */
	if (opt)
	  *opt = arg + 2;
	return ARG_LONG_OPTION;

      default:
	/* Short option. But if ARGP_LONG_ONLY, it can also be a long option. */

	if (opt)
	  *opt = arg + 1;

	if (parser->state.flags & ARGP_LONG_ONLY)
	  {
	    /* Rules from getopt.c:

	       If long_only and the ARGV-element has the form "-f",
	       where f is a valid short option, don't consider it an
	       abbreviated form of a long option that starts with f.
	       Otherwise there would be no way to give the -f short
	       option.

	       On the other hand, if there's a long option "fubar" and
	       the ARGV-element is "-fu", do consider that an
	       abbreviation of the long option, just like "--fu", and
	       not "-f" with arg "u".

	       This distinction seems to be the most useful approach. */

	    assert(parser->short_opts);
	    
	    if (arg[2] || !strchr(parser->short_opts, arg[1]))
	      return ARG_LONG_ONLY_OPTION;
	  }

	return ARG_SHORT_OPTION;
      }
  
  else
    return ARG_ARG;
}

/* Parse the next argument in PARSER (as indicated by PARSER->state.next).
   Any error from the parsers is returned, and *ARGP_EBADKEY indicates
   whether a value of EBADKEY is due to an unrecognized argument (which is
   generally not fatal).  */
static error_t
parser_parse_next (struct parser *parser, int *arg_ebadkey)
{
  if (parser->state.quoted && parser->state.next < parser->state.quoted)
    /* The next argument pointer has been moved to before the quoted
       region, so pretend we never saw the quoting `--', and start
       looking for options again. If the `--' is still there we'll just
       process it one more time. */
    parser->state.quoted = parser->args_only = 0;

  /* Give FIRST_NONOPT & LAST_NONOPT rational values if NEXT has been
     moved back by the user (who may also have changed the arguments).  */
  if (parser->last_nonopt > parser->state.next)
    parser->last_nonopt = parser->state.next;
  if (parser->first_nonopt > parser->state.next)
    parser->first_nonopt = parser->state.next;

  if (parser->nextchar)
    /* Deal with short options. */
    {
      struct group *group;
      char c;
      const struct argp_option *option;
      char *value = NULL;;

      assert(!parser->args_only);

      c = *parser->nextchar++;
      
      option = find_short_option(parser, c, &group);
      if (!option)
	{
	  if (parser->posixly_correct)
	    /* 1003.2 specifies the format of this message.  */
	    printf(
		     dgettext(parser->state.root_argp->argp_domain,
			      "%s: illegal option -- %c\n"),
		     parser->state.name, c);
	  else
	    printf(
		     dgettext(parser->state.root_argp->argp_domain,
			      "%s: invalid option -- %c\n"),
		     parser->state.name, c);

	  *arg_ebadkey = 0;
	  return EBADKEY;
	}

      if (!*parser->nextchar)
	parser->nextchar = NULL;

      if (option->arg)
	{
	  value = parser->nextchar;
	  parser->nextchar = NULL;
	      
	  if (!value
	      && !(option->flags & OPTION_ARG_OPTIONAL))
	    /* We need an mandatory argument. */
	    {
	      if (parser->state.next == parser->state.argc)
		/* Missing argument */
		{
		  /* 1003.2 specifies the format of this message.  */
		  printf(
			   dgettext(parser->state.root_argp->argp_domain,
				    "%s: option requires an argument -- %c\n"),
			   parser->state.name, c);

		  *arg_ebadkey = 0;
		  return EBADKEY;
		}
	      value = parser->state.argv[parser->state.next++];
	    }
	}
      return group_parse(group, &parser->state,
			 option->key, value);
    }
  else
    /* Advance to the next ARGV-element.  */
    {
      if (parser->args_only)
	{
	  *arg_ebadkey = 1;
	  if (parser->state.next >= parser->state.argc)
	    /* We're done. */
	    return EBADKEY;
	  else
	    return parser_parse_arg(parser,
				    parser->state.argv[parser->state.next]);
	}
      
      if (parser->state.next >= parser->state.argc)
	/* Almost done. If there are non-options that we skipped
	   previously, we should process them now. */
	{
	  *arg_ebadkey = 1;
	  if (parser->first_nonopt != parser->last_nonopt)
	    {
	      exchange(parser);
	      
	      /* Start processing the arguments we skipped previously. */
	      parser->state.next = parser->first_nonopt;
	      
	      parser->first_nonopt = parser->last_nonopt = 0;

	      parser->args_only = 1;
	      return 0;
	    }
	  else
	    /* Indicate that we're really done. */
	    return EBADKEY;
	}
      else
	/* Look for options. */
	{
	  char *arg = parser->state.argv[parser->state.next];

	  char *optstart;
	  enum arg_type token = classify_arg(parser, arg, &optstart);
	  
	  switch (token)
	    {
	    case ARG_ARG:
	      switch (parser->ordering)
		{
		case PERMUTE:
		  if (parser->first_nonopt == parser->last_nonopt)
		    /* Skipped sequence is empty; start a new one. */
		    parser->first_nonopt = parser->last_nonopt = parser->state.next;

		  else if (parser->last_nonopt != parser->state.next)
		    /* We have a non-empty skipped sequence, and
		       we're not at the end-point, so move it. */
		    exchange(parser);

		  assert(parser->last_nonopt == parser->state.next);
		  
		  /* Skip this argument for now. */
		  parser->state.next++;
		  parser->last_nonopt = parser->state.next; 
		  
		  return 0;

		case REQUIRE_ORDER:
		  /* Implicit quote before the first argument. */
		   parser->args_only = 1;
		   return 0;
		   
		case RETURN_IN_ORDER:
		  *arg_ebadkey = 1;
		  return parser_parse_arg(parser, arg);

		default:
            exit(1);
		}
	    case ARG_QUOTE:
	      /* Skip it, then exchange with any previous non-options. */
	      parser->state.next++;
	      assert (parser->last_nonopt != parser->state.next);

	      if (parser->first_nonopt != parser->last_nonopt)
		{
		  exchange(parser);
		  
		  /* Start processing the skipped and the quoted
		     arguments. */

		  parser->state.quoted = parser->state.next = parser->first_nonopt;

		  /* Also empty the skipped-list, to avoid confusion
		     if the user resets the next pointer. */
		  parser->first_nonopt = parser->last_nonopt = 0;
		}
	      else
		parser->state.quoted = parser->state.next;

	      parser->args_only = 1;	      
	      return 0;

	    case ARG_LONG_ONLY_OPTION:
	    case ARG_LONG_OPTION:
	      {
		struct group *group;
		const struct argp_option *option;
		char *value;

		parser->state.next++;
		option = find_long_option(parser, optstart, &group);
		
		if (!option)
		  {
		    /* NOTE: This includes any "=something" in the output. */
		    printf(
			     dgettext(parser->state.root_argp->argp_domain,
				      "%s: unrecognized option `%s'\n"),
			     parser->state.name, arg);
		    *arg_ebadkey = 0;
		    return EBADKEY;
		  }

		value = strchr(optstart, '=');
		if (value)
		  value++;
		
		if (value && !option->arg)
		  /* Unexpected argument. */
		  {
		    if (token == ARG_LONG_OPTION)
		      /* --option */
		      printf(
			       dgettext(parser->state.root_argp->argp_domain,
					"%s: option `--%s' doesn't allow an argument\n"),
			       parser->state.name, option->name);
		    else
		      /* +option or -option */
		      printf(
			       dgettext(parser->state.root_argp->argp_domain,
					"%s: option `%c%s' doesn't allow an argument\n"),
			       parser->state.name, arg[0], option->name);

		    *arg_ebadkey = 0;
		    return EBADKEY;
		  }
		
		if (option->arg && !value
		    && !(option->flags & OPTION_ARG_OPTIONAL))
		  /* We need an mandatory argument. */
		  {
		    if (parser->state.next == parser->state.argc)
		      /* Missing argument */
		      {
			if (token == ARG_LONG_OPTION)
			  /* --option */
			  printf(
				   dgettext(parser->state.root_argp->argp_domain,
					    "%s: option `--%s' requires an argument\n"),
				 parser->state.name, option->name);
			else
			  /* +option or -option */
			  printf(
				   dgettext(parser->state.root_argp->argp_domain,
					    "%s: option `%c%s' requires an argument\n"),
				   parser->state.name, arg[0], option->name);

			*arg_ebadkey = 0;
			return EBADKEY;
		      }

		    value = parser->state.argv[parser->state.next++];
		  }
		*arg_ebadkey = 0;
		return group_parse(group, &parser->state,
				   option->key, value);
	      }
	    case ARG_SHORT_OPTION:
	      parser->state.next++;
	      parser->nextchar = optstart;
	      return 0;

	    default:
	      exit(1);
	    }
	}
    }
}

/* Parse the options strings in ARGC & ARGV according to the argp in ARGP.
   FLAGS is one of the ARGP_ flags above.  If END_INDEX is non-NULL, the
   index in ARGV of the first unparsed option is returned in it.  If an
   unknown option is present, EINVAL is returned; if some parser routine
   returned a non-zero value, it is returned; otherwise 0 is returned.  */
error_t
argp_parse (const struct argp *argp, int argc, char **argv, unsigned flags,
	      int *end_index, void *input)
{
  error_t err;
  struct parser parser;

  /* If true, then err == EBADKEY is a result of a non-option argument failing
     to be parsed (which in some cases isn't actually an error).  */
  int arg_ebadkey = 0;

  if (! (flags & ARGP_NO_HELP))
    /* Add our own options.  */
    {
      struct argp_child *child = alloca (4 * sizeof (struct argp_child));
      struct argp *top_argp = alloca (sizeof (struct argp));

      /* TOP_ARGP has no options, it just serves to group the user & default
	 argps.  */
      memset (top_argp, 0, sizeof (*top_argp));
      top_argp->children = child;

      memset (child, 0, 4 * sizeof (struct argp_child));

      if (argp)
	(child++)->argp = argp;
      (child++)->argp = &argp_default_argp;
      if (argp_program_version || argp_program_version_hook)
	(child++)->argp = &argp_version_argp;
      child->argp = 0;

      argp = top_argp;
    }

  /* Construct a parser for these arguments.  */
  err = parser_init (&parser, argp, argc, argv, flags, input);

  if (! err)
    /* Parse! */
    {
      while (! err)
	err = parser_parse_next (&parser, &arg_ebadkey);
      err = parser_finalize (&parser, err, arg_ebadkey, end_index);
    }

  return err;
}
#ifdef weak_alias
weak_alias (__argp_parse, argp_parse)
#endif

/* Return the input field for ARGP in the parser corresponding to STATE; used
   by the help routines.  */
void *
__argp_input (const struct argp *argp, const struct argp_state *state)
{
  if (state)
    {
      struct group *group;
      struct parser *parser = state->pstate;

      for (group = parser->groups; group < parser->egroup; group++)
	if (group->argp == argp)
	  return group->input;
    }

  return 0;
}
#ifdef weak_alias
weak_alias (__argp_input, _argp_input)
#endif

/* Defined here, in case a user is not inlining the definitions in
 * argp.h */
void
argp_usage (__const struct argp_state *__state)
{
//   __argp_state_help (__state, ARGP_HELP_STD_USAGE);
}

int
__option_is_short (__const struct argp_option *__opt)
{
  if (__opt->flags & OPTION_DOC)
    return 0;
  else
    {
      int __key = __opt->key;
      /* FIXME: whether or not a particular key implies a short option
       * ought not to be locale dependent. */
      return __key > 0 && isprint (__key);
    }
}

int
__option_is_end (__const struct argp_option *__opt)
{
  return !__opt->key && !__opt->name && !__opt->doc && !__opt->group;
}

#endif
