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

1.2) Should be buildable and runnable on multiple platforms including the ones
     used in the continues integration context (when they support the features
     needed for these tests like process creation).

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
After a discussion with a few people (different people in different meetings),
it was decided to go in the following direction.

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
// Multiple tests within one file is possible.
// This test has three processes.
//

// You can provide an environment to your process.
// These system environment variables will be exported when a process starts.
mpt_env_var_t environment_1[] = {
  { "CYCLONEDDS_URI", "file://config1.xml" },
  { "PERMISSIONS", "..." },
  { "GOVERNANCE",  "..." },
  ...
  { NULL,          NULL  }
};
MPT_Process(suitename, testname_B, process_A, .environments=environment_1)
{
    ...
}

// Another process can use the same environment.
MPT_Process(suitename, testname_B, process_B, .environments=environment_1)
{
    ...
}

// Another process within the test can use a different environment.
mpt_env_var_t environment_2[] = {
  { "CYCLONEDDS_URI", "file://config2.xml" },
  { "PERMISSIONS", "..." },
  { "GOVERNANCE",  "..." },
  ...
  { NULL,          NULL  }
};
MPT_Process(suitename, testname_B, process_C, .environments=environment_2)
{
    ...
}



//
// Test suitename_testname_C
// You can also have a test with one process, but why would you do that?
//

// Other process fixtures are also possible
void setup(void)
{
    // Do stuff like setting up readers/writers, registering log callback, etc.
}
void teardown(void)
{
    // Do stuff like closing reader/writers, etc.
}
MPT_Process(suitename, testname_C, only_process, .init=setup, .fini=teardown, .timeout=10)
{
    ...
}



//
// Test suitename_testname_D
// Processes within a test can communicate, for instance to sync.
//
MPT_Process(suitename, testname_D, process_1, .environments=environment_1, .timeout=10)
{
    // Wait for another process to reach a state.
    mpt_waitfor(process_2, "continue");
    ...
}

MPT_Process(suitename, testname_D, process_2, .environments=environment_2, .timeout=10)
{
    mpt_send("continue");
    ...
}
```

##### MultiProcessTest header mpt.h
```cpp
#ifndef MPT_H_INCLUDED
#define MPT_H_INCLUDED

typedef struct {
    const char *name;
    const char *value;
} mpt_env_var_t;

typedef enum {
  MPT_SUCCESS = 0,
  MPT_FAILURE
  /* FIXME: More specific errors can at some point be introduced. A good
            example (maybe even use the values) would be sysexits.h. */
} mpt_retval_t;

typedef struct {
  //
  // FIXME: implement
  //   - the socket to use for synchronization (could just be a pipe or
  //       something too)...
  //
  //
} mpt_args_t;

typedef void(*mpt_test_t)(
  const mpt_args_t *mpt__args__, mpt_retval_t *mpt__retval__, mpt_env_var_t *env);

//
// MPT_Process signature
//
// this is used by cmake to recognize a given test
// it's expanded to a function signature.. this will be added to the list
//   ..
#define MPT_Process(suite, test, process) \
  MPT__ ## suite ## _ ## test ## _ ## process ( \
    const mpt_args_t *mpt__args__, mpt_retval_t *mpt__retval__, mpt_env_var_t *env)

#define MPT__ASSERT__(cond, ...) \
  do { \
    if (!(cond)) { \
      if (*mpt__retval__ == MPT_SUCCESS) { \
        *mpt__retval__ = MPT_FAILURE; \
      } \
      mpt_printf(__VA_ARGS__); \
    } \
  } while (0)

// supports printing a message...
// so could be written as MPT_ASSERT(a != b, "foo: %s\n", "bar")
// or: MPT_ASSERT(a != b)
#define MPT_ASSERT(...) \
  MPT__ASSERT__(__VA_ARGS__)

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
// *the runner forks the processes and ensures that they're passed the right
//  environment variables and arguments etc
//  >> maybe it'll open up the communication socket to
//  >> at least it handles all the communication between the various processes
//    >> or synchronization really... it'll probably just use select... but we
//       could use e.g. epoll on linux, kqueue on macOS and waitforsingleobject
//       on windows...
//  >> it also waits for all the processes to terminate... fetch their exit
//     codes... ensure their logs are properly written
//  >> cleans up if the process fails
//  >> so actually... also creates a working directory... maybe even chroots
//     the process and whatnot!
//

typedef struct {
  //
  // function
  // name of the process
  //
  //// must have some arguments.... ////
  //
  //
  //
} mpt_proc_t;

typedef struct {
  //
  //
  //
} mpt_test_t;

typedef struct {
  //
} mpt_suite_t;


//
//
//
int testwrapper(int argc, char *argv[])
{
  //
  // this little wrapper function is actually executed into
  //   fork > exec > enters this function
  // this also sets the name of the test process currently executing...
  //
  mpt_retval_t rv = MPT_SUCCESS;

  //
  // based on certain input it would open-up a socket to the control process
  // which advertises where it can connect! it would specifically not connect
  // on a peer-to-peer base
  //

  return (int)rv;
}

bool mpt_suite_exists(const char *suite)
{
  // dummy implementation of course!
  return (suite == NULL);
}

void mpt_add_suite(
  const char *suite)
{
  if (!mpt_suite_exists(suite)) {
    //suite = strdup(suite);
  }
}

void mpt_add_test(
  const char *suite,
  const char *test)
{
  // x. add a new test to the suite if it does not exist
  assert(suite != NULL);
  assert(test != NULL);
}

void mpt_add_process(
  const char *suite,
  const char *test,
  const char *process,
  mpt_test_t func)
{
  //
  // x. add a new process to an existing testcase
  //    .. this'll form a list that's started and watched by a given runner
  //
}
```
