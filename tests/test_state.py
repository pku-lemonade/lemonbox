"""Real competing writers and nested lifecycle locks."""
import multiprocessing
from pathlib import Path
import tempfile
import unittest

from vm.config import Config
from vm.state import ProfileState


def config():
    return Config.from_dict({"version": 1})


def stale_writer(directory, field, value, barrier, result):
    store = ProfileState(directory)
    revision = store.revision()
    candidate = Config.load(store.config_path)
    candidate.vm[field] = value
    barrier.wait()
    try:
        store.save_config(candidate,expected_revision=revision)
        result.put('saved')
    except ValueError:
        result.put('conflict')


def locked_writer(directory,field,value,barrier):
    store = ProfileState(directory)
    barrier.wait()
    with store.lock():
        candidate = Config.load(store.config_path)
        candidate.vm[field] = value
        store.save_config(candidate)


class ProfileLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name); self.state.chmod(0o700)
        config().write(self.state/'config.json')

    def workers(self,target,with_result=False):
        context = multiprocessing.get_context('fork')
        barrier = context.Barrier(2)
        results = context.Queue()
        children = []
        for field,value in (('cpus',4),('memory_mib',8192)):
            args = [self.state,field,value,barrier]
            if with_result: args.append(results)
            child = context.Process(target=target,args=args); children.append(child); child.start()
        for child in children:
            child.join(10)
            if child.is_alive(): child.kill(); child.join(); self.fail('Profile mutation lock deadlocked')
            self.assertEqual(child.exitcode,0)
        return results

    def test_concurrent_stale_edit_is_explicit_conflict(self):
        result = self.workers(stale_writer,True)
        self.assertEqual(sorted([result.get(timeout=2),result.get(timeout=2)]),['conflict','saved'])

    def test_serialized_read_modify_write_preserves_independent_changes(self):
        self.workers(locked_writer)
        candidate = Config.load(self.state/'config.json')
        self.assertEqual((candidate.vm['cpus'],candidate.vm['memory_mib']),(4,8192))

    def test_different_instances_share_nested_lock(self):
        first,second = ProfileState(self.state),ProfileState(self.state)
        with first.lock(), second.lock():
            second.save_config(config())
        self.assertFalse((self.state/'.lock').stat().st_mode & 0o077)

    def test_creation_revision_detects_competing_first_setup(self):
        store = ProfileState(self.state)
        with self.assertRaisesRegex(ValueError,'changed while'):
            store.save_config(config(),expected_revision=None)


if __name__ == '__main__': unittest.main()
