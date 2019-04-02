# Eclipse Cyclone DDS Multi Process Testing

Some features and functionalities of Cyclone DDS can only be tested when
there's communication between processes. Examples are durability, security,
etc. To really make sure that these kind of features work, extended tests
with multiple processes are needed.

This results in a number of [requirements](mpt_req.md).

There doesn't seem to be a 3rd party test framework that addresses our
requirements in a satisfactory manner.

This document will provide a design overview of the MPT.

Some simple usage examples can be found [here](mpt_usage.md).

## Design overview

TODO<br>
Currently only some code considerations and attempts are present.
This should be removed in favour of a proper design overview.

Short explanation.
CMake will scan the test files. It will create a runner source
file depending on the various MPT_TestProcess() it found.
This runner will take care of the actual starting and stopping
of the processes.

##### MultiProcessTest header mpt.h
Ignoring special Windows macro tricks for clarity.
```cpp
#ifndef MPT_H_INCLUDED
#define MPT_H_INCLUDED

typedef struct {
    const char *name;
    const char *value;
} mpt_env_var_t;

typedef struct mpt_env_ {
    struct mpt_env_ *parent;
    mpt_env_var_t vars[];
} mpt_env_t;

typedef enum {
  MPT_SUCCESS = 0,
  MPT_FAILURE
} mpt_retval_t;

typedef void(*mpt_process_init_func_t)(void);
typedef void(*mpt_process_fini_func_t)(void);

typedef struct {
    mpt_process_init_func_t init;
    mpt_process_fini_func_t fini;
    mpt_env_t *environment;
} mpt_data_t;


int mpt_patmatch(const char *pat, const char *str);
void mpt_export_env(const mpt_env_t *env);

#define MPT_ProcessArgs     mpt__args__, mpt__retval__
#define MPT_ProcessArgsSyntax \
    const mpt_data_t *mpt__args__, mpt_retval_t *mpt__retval__

#define MPT_Args(...) MPT_ProcessArgsSyntax, __VA_ARGS__
#define MPT_NoArgs() MPT_ProcessArgsSyntax

#define MPT_ArgValues(...) MPT_ProcessArgs, __VA_ARGS__
#define MPT_NoArgValues() MPT_ProcessArgs

#define MPT_ProcessEntryName(process) \
  MPT_ProcessEntry__ ## process

#define MPT_ProcessEntry(process, args)\
void MPT_ProcessEntryName(process)(args)


#define MPT_TestProcessName(suite, test, name) \
    MPT_TestProcess__##suite##_##test##_##name

#define MPT_TestProcessDeclaration(suite, test, name) \
void MPT_TestProcessName(suite, test, name) (MPT_ProcessArgsSyntax)


#define MPT_TestProcess(suite, test, name, process, args, ...)  \
MPT_TestProcessDeclaration(suite, test, name) {                 \
  mpt_data_t data = MPT_Fixture(__VA_ARGS__);                   \
                                                                \
  mpt_export_env(data.environment);                             \
                                                                \
  if (data.init != NULL) {                                      \
    data.init();                                                \
  }                                                             \
                                                                \
  MPT_ProcessEntryName(process)(args);                          \
                                                                \
  if (data.fini != NULL) {                                      \
    data.fini();                                                \
  }                                                             \
}

#define MPT_Test(...) /* TODO: Add test fixtures. */



//
// MPT_ASSERT
//
#define MPT__ASSERT__(cond, ...) \
  do { \
    if (!(cond)) { \
      if (*mpt__retval__ == MPT_SUCCESS) { \
        *mpt__retval__ = MPT_FAILURE; \
      } \
      printf(__VA_ARGS__); \
      printf("\n"); \
    } \
  } while(0)

#define MPT__ASSERT_FATAL__(cond, ...) \
  do { \
    if (!(cond)) { \
      if (*mpt__retval__ == MPT_SUCCESS) { \
        *mpt__retval__ = MPT_FAILURE; \
      } \
      printf(__VA_ARGS__); \
      printf("\n"); \
      return; \
    } \
  } while(0)

#define MPT_ASSERT(...) \
  MPT__ASSERT__(__VA_ARGS__)

#define MPT_ASSERT_FATAL(...) \
  MPT__ASSERT_FATAL__(__VA_ARGS__)



//
// Expand the process fixtures.
//
#define MPT_Comma() ,
#define MPT_Reduce(one, ...) one

#define MPT_Fixture__(throw, away, value, ...) value

#define MPT_Fixture(...) \
  MPT_Fixture_( MPT_Comma MPT_Reduce(__VA_ARGS__,) (), __VA_ARGS__ )

#define MPT_Fixture_(throwaway, ...) \
  MPT_Fixture__(throwaway, ((mpt_data_t){ 0 }), ((mpt_data_t){ __VA_ARGS__ }))

#endif /* MPT_H_INCLUDED */
```

##### MultiProcessTest runner
```cpp
//
// some simple functions that can be used to easily generate a runner
//

//
// - suite
//    - test
//       - process  \
//       - process  |- these are all managed a single runner*
//       - process  /
//
// *The runner
//     - starts the processes and ensures that they're passed the right
//       environment variables.
//     - maybe open up the communication socket, pipe or something else
//       to facilitate the IPC between the child processes.
//     - waits for all processes to terminate and fetch their exit codes.
//     - determines test result according to process results.
//     - cleans up if the process fails.
//     - could possibly do additional stuff like creating a working
//       directory of even chroots the process and whatnot.
//

//
// The structures to setup a suite-test-process tree.
//
typedef void(*mpt_func_proc_t)(
  const mpt_data_t *mpt__args__, mpt_retval_t *mpt__retval__);

typedef struct mpt_process_ {
    const char* name;
    ddsrt_pid_t pid;
    mpt_func_proc_t process;
    struct mpt_process_ *next;
} mpt_process_t;

typedef struct mpt_test_ {
    const char* name;
    mpt_process_t *procs;
    struct mpt_test_ *next;
} mpt_test_t;

typedef struct mpt_suite_ {
    const char* name;
    mpt_test_t *tests;
    struct mpt_suite_ *next;
} mpt_suite_t;

//
// Imagine support functions to allocate structures, add them to the
// suite/test tree, find specific tests/processes, free stuff, etc.
//
// The calls to create and add the structures will be generated
// by cmake.
//

//
// Then we have the actual test runner.
//
// It'll take a suite and test. Then it'll start every process of
// that test by restarting this application (identified by exe) a
// few times with the proper arguments to identify those processes.
//
// To get the main() to call the proper process entry function, it
// needs to be able to identify the suite, test and process. This is
// done by the supplying -s(uite), -t(est) and -p(rocess) arguments.
//
static int
mpt_run_test(const char *exe, mpt_suite_t *suite, mpt_test_t *test)
{
    char *argv[] = { NULL, NULL,   NULL, NULL,   NULL, NULL,   NULL, NULL };
    mpt_process_t *proc;

    argv[0] = "-s";
    argv[1] = (char*)suite->name;
    argv[2] = "-t";
    argv[3] = (char*)test->name;

    /* Start the processes. */
    proc = test->procs;
    while (proc) {
        argv[4] = "-p";
        argv[5] = (char*)proc->name;
        ddsrt_process_create(exe, argv, &proc->pid);
        proc = proc->next;
    }
    /* Wait for the processes. */
    while (not_timeout && not_all_procs_stopped) {
        proc = test->procs;
        while (proc) {
            int32_t status;
            if (get_process_exit_code(proc->pid, &status) == DDS_RETCODE_OK) {
                Determine test result succes/fail according to status.
            }
            proc = proc->next;
        }
        dds_sleepfor(DDS_MSECS(50));
    }
    if (not_all_procs_stopped) {
        Kill remaining child processes.
    }
    return result;
}
static int
mpt_run_tests(const char *exe, const char *spattern, const char *tpattern)
{
    while (run through the suite/test tree) {
        if (suite/test in tree matches the patterns) {
            mpt_run_test(exe, suite, test);
        }
    }
}

//
// When indicated, in the main(), we should only call the entry function
// of a given process.
//
static int
mpt_run_proc(mpt_process_t *proc)
{
    mpt_retval_t retval = MPT_SUCCESS;
    mpt_data_t   args;
    proc->process(&args, &retval);
    return (retval == MPT_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
static int
mpt_run_procs(const char *spattern, const char *tpattern, const char *ppattern)
{
    while (run through the suite/test/processes tree) {
        if (suite/test/process in tree matches the patterns) {
            mpt_run_proc(proc);
        }
    }
}

//
// The main() determines if it should run test(s) or call
// an process entry function.
//
int main(int argc, char *argv[])
{
    Parse options.

    // Generated by cmake
    Add suites.
    Add tests to proper suites.
    Add processes to proper tests.
    // Generated by cmake

    if (no process selected) {
        /* Run test(s). */
        result = mpt_run_tests(argv[0], opts.suite, opts.test);
    } else {
        /* Run process(es). */
        result = mpt_run_procs(opts.suite, opts.test, opts.process);
    }

    return result;
}
```
