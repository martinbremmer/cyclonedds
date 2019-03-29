# Eclipse Cyclone Multi Process Testing

Most of the testing done in Cyclone is geared toward unit testing. These should
be quick and shouldn't need much environment setup and certainly not different
processes.

However, some features/functionality of DDS are not that easy to test in a
single process. Examples are durability, security, etc. To really make sure
that these kind of features work, extended tests with multiple processes are
needed.


## Requirements
1.1) Be able to test features using multiple processes.

1.2) Should be buildable and runnable on multiple platforms (like windows,
     linux, mac, etc) including the ones used in the continues integration
     context (when they support the features needed for these tests like
     process creation).

1.3) Results should be easily analyzable within the continues integration
     context and when running locally.

1.4) No processes should stay alive (f.i. deadlock in child process) when the
     test finished (or timed out).

1.5) When running tests parallel, they should not interfere with each other.

1.6) Processes of the same test should be able to communicate (for settings,
     syncing, etc).

1.7) It should be possible to analyze output/messages/tracing of the parent
     and child processes to be able to draw a proper test conclusion.


## Considerations
2.1)
The files that actually contain the tests, should be focused on those tests.
This means that the process management and setting up (and usage of) IPC
between test processes should be handled by a test framework so that the
test files can remain as clean as possible.

2.2)
If possible, there shouldn't be a need for writing log files to a file system
when running the tests normally. It could be helpful, however, that these log
files are written when debugging related tests.

2.3)
Preferably, the DDS communication between the processes should not leave
localhost.


## Intentions
There doesn't seem to be a 3rd party test framework that addresses our
requirements in a satisfactory manner.

After some discussions with a few people (different people in different
meetings), it was decided to create our own framework and to go in the
following direction:

- Process creation/destruction/etc is (re)introduced in the ddsrt. It will be
  stripped down versions of the code from Vortex OpenSplice.<br>
  [1.1/1.2]

- The files that contain the tests, should be easy to understand and focus on
  the tests themselves.<br>
  [2.1]

- Other files (generated or in the framework) should take care of the
  intricacies of starting/monitoring the proper processes with the proper
  settings.<br>
  [1.4/1.6/2.1]

- To do this, a similar approach of the current CUnit build will be used;
  CMake will scan the test files and create runners according to macros within
  the test files.<br>
  [2.1]

- The tests should be executed by CTest. For now this means that a proper
  runner exit code for pass/fail is enough. We would like to add CUnit like
  output in the future.<br>
  [1.2/1.3]

- The Cyclone dds API contains the possibility to monitor generated log traces.
  This means we won't be needing to monitor actual log files. Just register a
  log callback and go from there.<br>
  [1.7/2.2]

- The framework should be able to generate unique domain ids and unique topic
  names when necessary. That way, tests won't interfere with each other when
  running in parallel.<br>
  [1.5]

This results in the following concept files. Please keep in mind that they are
very preliminary and many details will probably change or added when actually
implementing.<br>
But it should provide the bigger picture of where we'd like to go.

Also, keep in mind that we don't want to provide this in one big bang, but in
bite sized chunks when possible.

##### Test file
```cpp
#include "mpt/mpt.h" // Multi-Process-Tests framework

//
// Test suitename_testname_A
//
// A simple test that starts two processes
//

// This process is part of test suitename_testname_A.
MPT_Process(suitename, testname_A, process_A)
{
    // Do stuff
    ...

    // The test processes will use asserts to indicate success/failures.
    MPT_ASSERT(1, "The problem is: %s", "existential crisis");

    // No need to return anything, that's handled by the assert calls.
}

// This process is part of test suitename_testname_A and will be executed
// in parallel with suitename_testname_A::process_A.
MPT_Process(suitename, testname_A, process_B)
{
    ...
}



//
// Test suitename_testname_B
//
// Multiple tests within one file is possible.
// This test has three processes with various environments.
//

// These system environment variables will be exported when a process starts.
mpt_env_t environment_1 = {
  NULL,
  {
    { "CYCLONEDDS_URI", "file://config1.xml"     },
    { "PERMISSIONS",    "file://permissions.p7s" },
    { "GOVERNANCE",     "file://governance.p7s"  },
    { NULL,             NULL                     }
  }
};
MPT_Process(suitename, testname_B, process_A, .environment=environment_1)
{
    ...
}

// Another process can use the same environment.
MPT_Process(suitename, testname_B, process_B, .environment=environment_1)
{
    ...
}

// Another process within the test can use a different environment.
mpt_env_t environment_2 = {
  NULL,
  {
    { "CYCLONEDDS_URI", "file://config2.xml"     },
    { "PERMISSIONS",    "file://permissions.p7s" },
    { "GOVERNANCE",     "file://governance.p7s"  },
    { "ANOTHER_VALUE",  "..."                    },
    { NULL,             NULL                     }
  }
};
MPT_Process(suitename, testname_B, process_C, .environment=environment_2)
{
    ...
}



//
// Test suitename_testname_C
//
// The two environments in the previous example are partly the same.
// It's possible to inherit environments. The following test is actually
// the same as the previous one.
//

mpt_env_t environment_default = {
  NULL,                          /* inheritance */
  {
    { "CYCLONEDDS_URI", "file://config1.xml"     },
    { "PERMISSIONS",    "file://permissions.p7s" },
    { "GOVERNANCE",     "file://governance.p7s"  },
    { NULL,             NULL  }
  }
};
MPT_Process(suitename, testname_C, process_A, .environment=environment_default)
{
    ...
}
MPT_Process(suitename, testname_C, process_B, .environment=environment_default)
{
    ...
}

// Inherit default environment, overrule one value and add another.
mpt_env_t environment_3 = {
  environment_default,       /* inheritance */
  {
    { "CYCLONEDDS_URI", "file://config2.xml" },
    { "ANOTHER_VALUE",  "..."                },
    { NULL,             NULL                 }
  }
};
MPT_Process(suitename, testname_C, process_C, .environment=environment_3)
{
    ...
}



//
// Test suitename_testname_D
//
// Other process fixtures are also possible.
// This test has just one process, but why would you do that normally?
//

void setup(void)
{
    // Do stuff like setting up readers/writers, registering log callback, etc.
}
void teardown(void)
{
    // Do stuff like closing reader/writers, etc.
}
MPT_Process(suitename, testname_D, only_process, .init=setup, .fini=teardown, .timeout=10)
{
    ...
}



//
// Test suitename_testname_E
//
// Processes within a test can communicate, for instance to sync.
//

MPT_Process(suitename, testname_E, process_1)
{
    // Wait for another process to reach a state.
    mpt_waitfor("process_2_started");
    ...
}

MPT_Process(suitename, testname_E, process_2)
{
    mpt_send("process_2_started");
    ...
}

MPT_Process(suitename, testname_E, process_3)
{
    mpt_waitfor("process_2_started");
    ...
}



//
// Test suitename_testname_F
//
// If you want to call a function from your process that can use MPT_ASSERTs, then that
// function has to have a syntax including MPT_ProcessArgsSyntax.
//

static void some_function(MPT_ProcessArgsSyntax, const char *text)
{
    MPT_ASSERT(1, text);
}

MPT_Process(suitename, testname_F, process)
{
    some_function(MPT_ProcessArgs, "placeholder");
}
```

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

#define MPT_ProcessName(suite, test, process) \
  MPT_Process__ ## suite ## _ ## test ## _ ## process

#define MPT_ProcessProxyName(suite, test, process) \
  MPT_Process_Proxy__ ## suite ## _ ## test ## _ ## process

#define MPT_ProcessDeclaration(suite, test, process) \
void MPT_ProcessName(suite, test, process) (MPT_ProcessArgsSyntax)

#define MPT_ProcessProxyDeclaration(suite, test, process) \
void MPT_ProcessProxyName(suite, test, process) (MPT_ProcessArgsSyntax)



//
// MPT_Process signature
//
// This is used by cmake to recognize a given process and to which test
// it belongs.
// It's expanded to a function signature. This will be added to a list
// and executed by the runner generated by cmake.
//
#define MPT_Process(suite, test, process, ...)             \
  static MPT_ProcessDeclaration(suite, test, process);     \
                                                           \
  MPT_ProcessProxyDeclaration(suite, test, process) {      \
    mpt_data_t data = MPT_Fixture(__VA_ARGS__);            \
                                                           \
    mpt_export_env(data.environment);                      \
                                                           \
    if (data.init != NULL) {                               \
      data.init();                                         \
    }                                                      \
                                                           \
    MPT_ProcessName(suite, test, process)                  \
                            (mpt__args__, mpt__retval__);  \
                                                           \
    if (data.fini != NULL) {                               \
      data.fini();                                         \
    }                                                      \
  }                                                        \
                                                           \
  static MPT_ProcessDeclaration(suite, test, process)



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
