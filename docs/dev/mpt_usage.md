# Eclipse Cyclone DDS Multi Process Testing Usage

This document presents some simple
[Multi Process Test Framework](multi_process_testing.md) API usage.

Please keep in mind that is stil somewhat preliminary and some details will
probably change or added when actually implementing.<br>
But it should provide the bigger picture of where we'd like to go.


##### Test file
```cpp
#include "mpt/mpt.h" // Multi-Process-Tests framework

//
// First, we need a process entry-point that can be used in tests.
//
//              |  name     | arguments   |
MPT_ProcessEntry(proc_noargs, MPT_NoArgs())
{
    // Do stuff
    ...

    // The test processes will use asserts to indicate success/failures.
    MPT_ASSERT(1, "The problem is: %s", "existential crisis");

    // No need to return anything, that's handled by the assert calls.
}

//
// A process entry-point can have arguments.
//
//              |  name   | arguments                            |
MPT_ProcessEntry(proc_args, MPT_Args(int domain, const char* text))
{
  int expected = 1;
  MPT_ASSERT(expected == domain, "proc_multipleargs(%d, %s)", domain, text);
}



//
// Test: suitename_testA
//
// A simple test that starts two processes. Because a test can use the same
// process entry-point to start multiple processes, each process has to have
// its own unique id within the test.
//
//             | process identification | entry-point | arguments        |
MPT_TestProcess(suitename, testA, id1,    proc_noargs,  MPT_NoArgValues());
MPT_TestProcess(suitename, testA, id2,    proc_noargs,  MPT_NoArgValues());
MPT_Test(suitename, testA);



//
// Test: suitename_testB
//
// Of course, different processes can be started as well.
// Argument values are provided per test process.
//
MPT_TestProcess(suitename, testB, id1, proc_noargs, MPT_NoArgValues(    ));
MPT_TestProcess(suitename, testB, id2, proc_args,   MPT_ArgValues(1, "2"));
MPT_TestProcess(suitename, testB, id3, proc_args,   MPT_ArgValues(1, "3"));
MPT_Test(suitename, testB);



//
// Test: suitename_testC
//
// The processes can have different or equal 'system environments'.
//
mpt_env_t environment_C1[] = {
  { "CYCLONEDDS_URI", "file://config1.xml"     },
  { "PERMISSIONS",    "file://permissions.p7s" },
  { "GOVERNANCE",     "file://governance.p7s"  },
  { NULL,             NULL                     }
};
mpt_env_t environment_C2[] = {
  { "CYCLONEDDS_URI", "file://config2.xml"     },
  { "PERMISSIONS",    "file://permissions.p7s" },
  { "GOVERNANCE",     "file://governance.p7s"  },
  { NULL,             NULL                     }
};
MPT_TestProcess(suitename, testC, id1, proc_noargs, MPT_NoArgValues(), .environment=environment_C1);
MPT_TestProcess(suitename, testC, id2, proc_noargs, MPT_NoArgValues(), .environment=environment_C1);
MPT_TestProcess(suitename, testC, id3, proc_noargs, MPT_NoArgValues(), .environment=environment_C2);
MPT_Test(suitename, testC);



//
// Test: suitename_testD
//
// The two environments in the previous example are partly the same.
// It's possible set the environment on test level. The environment variables
// related to the test are set before the ones related to a process. This 
// means that a process can overrule variables.
//
// The following test is the same as the previous one.
//
mpt_env_t environment_D1[] = {
  { "CYCLONEDDS_URI", "file://config1.xml"     },
  { "PERMISSIONS",    "file://permissions.p7s" },
  { "GOVERNANCE",     "file://governance.p7s"  },
  { NULL,             NULL                     }
};
mpt_env_t environment_D2[] = {
  { "CYCLONEDDS_URI", "file://config2.xml"     },
};
MPT_TestProcess(suitename, testD, id1, proc_noargs, MPT_NoArgValues());
MPT_TestProcess(suitename, testD, id2, proc_noargs, MPT_NoArgValues());
MPT_TestProcess(suitename, testD, id3, proc_noargs, MPT_NoArgValues(), .environment=environment_D2);
MPT_Test(suitename, testD, .environment=environment_D1);



//
// Test: suitename_testE
//
// The processes and tests can use init/fini fixtures.
// The test init is executed before the process init.
// The process fini is executed before the test fini.
//
void proc_setup(void)    { /* do stuff */ }
void proc_teardown(void) { /* do stuff */ }
void test_setup(void)    { /* do stuff */ }
void test_teardown(void) { /* do stuff */ }
MPT_TestProcess(suitename, testE, id1, proc_noargs, MPT_NoArgValues(), .init=proc_setup);
MPT_TestProcess(suitename, testE, id2, proc_noargs, MPT_NoArgValues(), .fini=proc_teardown);
MPT_TestProcess(suitename, testE, id3, proc_noargs, MPT_NoArgValues(), .init=proc_setup, .fini=proc_teardown);
MPT_Test(suitename, testE, .init=test_setup, .fini=test_teardown);



//
// Test: suitename_testF
//
// The timeout and disable options are handled by test fixtures.
//
MPT_TestProcess(suitename, testF, id1, proc_noargs,  MPT_NoArgValues());
MPT_TestProcess(suitename, testF, id2, proc_noargs,  MPT_NoArgValues());
MPT_Test(suitename, testF, .timeout=10, .disable=true);
```
