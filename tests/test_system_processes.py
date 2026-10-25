import dataclasses
import os
import unittest

from hotturkey.system_processes import JobProcesses,Process


class Kernel:
    def __init__(self):
        self.root=1000001;self.values={self.root:Process(self.root,501,501,501,self.root,4,1,0),
            self.root+1:Process(self.root+1,501,501,501,self.root,3,1,1),self.root+2:Process(self.root+2,501,501,501,self.root+2,3,1,2)}
        self.tree={self.root:[self.root+1],self.root+1:[self.root+2]}
    def process(self,pid):return self.values.get(pid)
    def children(self,pid):return self.tree.get(pid,[])
    def group(self,pgid):return [pid for pid,value in self.values.items() if value.pgid==pgid]


class ProcessTests(unittest.TestCase):
    def setUp(self):self.kernel=Kernel()
    def test_freezes_kernel_incarnation_and_watches_separate_descendant_groups(self):
        observer=JobProcesses(self.kernel.root,501,kernel=self.kernel)
        self.assertEqual(observer.groups,{self.kernel.root,self.kernel.root+2});self.assertTrue(observer.live())
        self.kernel.values.clear();self.assertFalse(observer.live())
    def test_parent_exit_is_not_enough_while_executor_survives(self):
        observer=JobProcesses(self.kernel.root,501,kernel=self.kernel);del self.kernel.values[self.kernel.root]
        self.assertTrue(observer.live())
        self.kernel.values.clear();self.assertFalse(observer.live())
    def test_zombies_do_not_count_as_executing_policy(self):
        observer=JobProcesses(self.kernel.root,501,kernel=self.kernel)
        self.kernel.values={pid:dataclasses.replace(value,status=5) for pid,value in self.kernel.values.items()}
        self.assertFalse(observer.live())
    def test_wait_expires_while_group_is_still_alive(self):
        observer=JobProcesses(self.kernel.root,501,kernel=self.kernel);now=[0]
        def remaining():
            if now[0]>=.2:raise TimeoutError('Expired')
            return .2-now[0]
        with self.assertRaises(TimeoutError):observer.wait(remaining,sleep=lambda amount:now.__setitem__(0,now[0]+amount))
        self.assertGreaterEqual(now[0],.2)
    def test_kernel_query_failure_never_means_quiescent(self):
        observer=JobProcesses(self.kernel.root,501,kernel=self.kernel)
        def failure(group):raise PermissionError('Denied')
        self.kernel.group=failure
        with self.assertRaises(PermissionError):observer.live()
    def test_changed_or_resumed_incarnation_rejected_before_unload(self):
        observer=JobProcesses(self.kernel.root,501,kernel=self.kernel);before=self.kernel.values[self.kernel.root]
        for value in [dataclasses.replace(before,status=3),dataclasses.replace(before,start_usec=1),dataclasses.replace(before,uid=0)]:
            self.kernel.values[self.kernel.root]=value
            with self.assertRaises(RuntimeError):observer.confirm_frozen()
    def test_foreign_uid_shared_caller_group_and_unpaused_parent_rejected(self):
        original=self.kernel.values[self.kernel.root]
        for value in [dataclasses.replace(original,status=3),dataclasses.replace(original,uid=0),dataclasses.replace(original,pgid=os.getpgrp())]:
            self.kernel.values[self.kernel.root]=value
            with self.assertRaises(PermissionError):JobProcesses(self.kernel.root,501,kernel=self.kernel)
    def test_child_privilege_changes_are_rejected(self):
        self.kernel.values[self.kernel.root+1]=dataclasses.replace(self.kernel.values[self.kernel.root+1],svuid=0)
        with self.assertRaises(PermissionError):JobProcesses(self.kernel.root,501,kernel=self.kernel)
    def test_reused_group_is_conservative_not_reported_stopped(self):
        observer=JobProcesses(self.kernel.root,501,kernel=self.kernel);self.kernel.values.clear()
        self.kernel.values[self.kernel.root+9]=Process(self.kernel.root+9,501,501,501,self.kernel.root,3,99,0)
        self.assertTrue(observer.live())


if __name__=='__main__':unittest.main()
